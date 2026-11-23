//go:build linux

package provisioning

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

var managedDNSPID = regexp.MustCompile(`(?m)^pid: ([0-9]+)\r?$`)

func managedDNSActivationPending(ctx context.Context, root, proc string) (bool, error) {
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil || len(entries) > 64 {
		return false, fmt.Errorf("managed DNS inventory unavailable or exceeds budget")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&0022 != 0 || info.Sys().(*syscall.Stat_t).Uid != 0 {
		return false, fmt.Errorf("managed DNS inventory untrusted")
	}
	for _, entry := range entries {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		if !entry.IsDir() {
			continue
		}
		directory := filepath.Join(root, entry.Name())
		info, err := os.Lstat(directory)
		if err != nil || info.Mode()&0022 != 0 || info.Sys().(*syscall.Stat_t).Uid != 0 {
			return false, fmt.Errorf("managed DNS network directory untrusted")
		}
		fd, err := syscall.Open(filepath.Join(directory, "dnsmasq.pid"), syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		if os.IsNotExist(err) {
			// A failed Incus network start can remove the pidfile. Existing
			// DHCP state still requires a verified DNS process, not an empty
			// receipt silently accepted as successful patch activation.
			if _, stateErr := os.Stat(filepath.Join(directory, "dnsmasq.hosts")); stateErr == nil {
				return true, nil
			} else if !os.IsNotExist(stateErr) {
				return false, fmt.Errorf("managed DNS state unavailable")
			}
			continue
		}
		if err != nil {
			return false, fmt.Errorf("managed DNS service receipt unavailable")
		}
		file := os.NewFile(uintptr(fd), "managed-dns-receipt")
		info, err = file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() > 65536 || info.Sys().(*syscall.Stat_t).Uid != 0 || info.Sys().(*syscall.Stat_t).Nlink != 1 || info.Mode()&0022 != 0 {
			file.Close()
			return false, fmt.Errorf("managed DNS service receipt untrusted")
		}
		data, readErr := io.ReadAll(io.LimitReader(file, 65537))
		file.Close()
		if readErr != nil || len(data) > 65536 {
			return false, fmt.Errorf("managed DNS service receipt exceeds budget")
		}
		matches := managedDNSPID.FindAllSubmatch(data, -1)
		if len(matches) != 1 {
			return false, fmt.Errorf("managed DNS process identity invalid")
		}
		pid, err := strconv.Atoi(string(matches[0][1]))
		if err != nil || pid < 2 {
			return false, fmt.Errorf("managed DNS process identity invalid")
		}
		process := filepath.Join(proc, strconv.Itoa(pid))
		name, err := os.ReadFile(filepath.Join(process, "comm"))
		if os.IsNotExist(err) {
			return true, nil
		}
		if err != nil || strings.TrimSpace(string(name)) != "dnsmasq" {
			return false, fmt.Errorf("managed DNS original process identity changed")
		}
		exe, err := os.Readlink(filepath.Join(process, "exe"))
		if err != nil || strings.TrimSuffix(exe, " (deleted)") != "/usr/sbin/dnsmasq" && strings.TrimSuffix(exe, " (deleted)") != "/usr/bin/dnsmasq" {
			return false, fmt.Errorf("managed DNS executable identity changed")
		}
		old, err := securityProcessLoaded(ctx, proc, pid)
		if err != nil || old {
			return old, err
		}
	}
	return false, nil
}
