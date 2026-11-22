//go:build linux

package provisioning

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Read host code mappings only. Never collect a guest process, mapped pathname,
// argv or environment in a status receipt. No service is stopped or restarted.
func securityLoadedState(ctx context.Context, proc string) (string, error) {
	namespace, err := os.Readlink(filepath.Join(proc, "1/ns/pid"))
	if err != nil {
		return "", err
	}
	entries, err := os.ReadDir(proc)
	if err != nil {
		return "", err
	}
	checked := 0
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		if err := ctx.Err(); err != nil {
			return "", err
		}
		root := filepath.Join(proc, entry.Name())
		ns, err := os.Readlink(filepath.Join(root, "ns/pid"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return "", err
		}
		if ns != namespace {
			continue
		}
		checked++
		if checked > 256 {
			return "", fmt.Errorf("host loaded-code budget exceeded")
		}
		file, err := os.Open(filepath.Join(root, "maps"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return "", err
		}
		limited := &io.LimitedReader{R: file, N: 1048577}
		scanner := bufio.NewScanner(limited)
		scanner.Buffer(make([]byte, 4096), 65536)
		old := false
		for scanner.Scan() {
			if err := ctx.Err(); err != nil {
				file.Close()
				return "", err
			}
			fields := strings.Fields(scanner.Text())
			if len(fields) < 6 || !strings.Contains(fields[1], "x") || !strings.HasSuffix(scanner.Text(), " (deleted)") {
				continue
			}
			path := fields[5]
			if strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "/dev/") && !strings.HasPrefix(path, "/memfd:") && !strings.HasPrefix(path, "/SYSV") {
				old = true
			}
		}
		scanErr := scanner.Err()
		file.Close()
		if scanErr != nil {
			return "", scanErr
		}
		if limited.N <= 0 {
			return "", fmt.Errorf("host loaded-code mapping budget exceeded")
		}
		if old {
			return "activation-required", nil
		}
	}
	return "checked", nil
}
