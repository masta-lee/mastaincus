//go:build linux

package provisioning

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const memoryWatermarkFile = "/etc/sysctl.d/91-incudal-memory.conf"
const memoryWatermarkJournal = "/var/lib/incudal-agent/memory-watermark.json"

type memoryWatermarkReceipt struct {
	Version  int
	BootID   string
	Previous int64
	Target   int64
}

func smallHostWatermark(meminfo string) int64 {
	for _, line := range strings.Split(meminfo, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[0] != "MemTotal:" || fields[2] != "kB" {
			continue
		}
		kb, err := strconv.ParseInt(fields[1], 10, 64)
		// The physically tested E2 class, with a conservative reserve floor.
		// Larger/unknown machines keep their existing kernel policy.
		if err != nil || kb < 900*1024 || kb > 1024*1024 {
			return 0
		}
		target := kb / 128
		if target < 8192 {
			target = 8192
		}
		return target
	}
	return 0
}

func watermarkConfig(target int64) string {
	return "# Incudal small standalone pool host; customer quota unchanged.\nvm.min_free_kbytes=" + strconv.FormatInt(target, 10) + "\n"
}

func readWatermarkFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 65536 || info.Mode()&0022 != 0 || info.Sys().(*syscall.Stat_t).Uid != 0 || info.Sys().(*syscall.Stat_t).Nlink != 1 {
		return nil, fmt.Errorf("memory policy file unsafe")
	}
	return os.ReadFile(path)
}

func operatorWatermark(configs map[string]string) bool {
	for path, text := range configs {
		if path == memoryWatermarkFile {
			continue
		}
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			key := strings.TrimLeft(strings.Fields(line)[0], "-")
			key = strings.SplitN(key, "=", 2)[0]
			if strings.ReplaceAll(key, "/", ".") == "vm.min_free_kbytes" {
				return true
			}
		}
	}
	return false
}

func writeWatermarkFile(path string, data []byte, mode os.FileMode) error {
	for dir := filepath.Dir(path); dir != "/"; dir = filepath.Dir(dir) {
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode()&0022 != 0 || info.Sys().(*syscall.Stat_t).Uid != 0 {
			return fmt.Errorf("memory policy directory unsafe")
		}
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".incudal-memory-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err = file.Chmod(mode); err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

// Called only after a verified compatibility daemon on an enabled pool host.
// This bounded optional optimization never affects readiness/stock on failure.
func reconcileMemoryWatermark(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return nil
	}
	release, err := releaseFile()
	if err != nil || !(strings.Contains(release, "ID=alpine") || strings.Contains(release, "ID=\"alpine\"")) {
		return nil
	}
	for _, namespace := range []string{"pid", "mnt"} {
		self, err := os.Stat("/proc/self/ns/" + namespace)
		init, initErr := os.Stat("/proc/1/ns/" + namespace)
		if err != nil || initErr != nil || !os.SameFile(self, init) {
			return nil
		}
	}
	meminfo, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return err
	}
	target := smallHostWatermark(string(meminfo))
	if target == 0 {
		return nil
	}
	return applyStandaloneMemoryWatermark(ctx, target)
}

func applyStandaloneMemoryWatermark(ctx context.Context, target int64) error {
	if target != 8192 {
		return fmt.Errorf("unverified memory reserve target")
	}
	info, err := run(ctx, "incus", "query", "/1.0")
	var server struct {
		Environment struct {
			Clustered *bool `json:"server_clustered"`
		} `json:"environment"`
	}
	if err != nil || json.Unmarshal(info, &server) != nil || server.Environment.Clustered == nil || *server.Environment.Clustered {
		return fmt.Errorf("standalone memory policy not confirmed")
	}
	unlock, err := lock()
	if err != nil {
		return err
	}
	defer unlock()
	configs := map[string]string{}
	paths := []string{"/etc/sysctl.conf"}
	for _, dir := range []string{"/etc/sysctl.d", "/run/sysctl.d", "/usr/local/lib/sysctl.d", "/usr/lib/sysctl.d", "/lib/sysctl.d"} {
		matches, err := filepath.Glob(dir + "/*.conf")
		if err != nil {
			return err
		}
		paths = append(paths, matches...)
	}
	for _, path := range paths {
		if path == memoryWatermarkFile {
			continue
		}
		data, err := readWatermarkFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		configs[path] = string(data)
	}
	operatorConfigured := operatorWatermark(configs)
	currentData, err := os.ReadFile("/proc/sys/vm/min_free_kbytes")
	if err != nil {
		return err
	}
	current, err := strconv.ParseInt(strings.TrimSpace(string(currentData)), 10, 64)
	if err != nil || current <= 0 {
		return fmt.Errorf("memory reserve unavailable")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return err
	}
	var receipt memoryWatermarkReceipt
	data, err := readWatermarkFile(memoryWatermarkJournal)
	if err == nil {
		if json.Unmarshal(data, &receipt) != nil || receipt.Version != 1 || receipt.Target < 8192 || receipt.Target > 16384 || receipt.Previous < receipt.Target || len(receipt.BootID) != 36 {
			return fmt.Errorf("memory reserve receipt invalid")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	config, configErr := readWatermarkFile(memoryWatermarkFile)
	if configErr == nil && (receipt.Version != 1 || string(config) != watermarkConfig(receipt.Target)) {
		return fmt.Errorf("explicit memory reserve configuration preserved")
	}
	if configErr != nil && !os.IsNotExist(configErr) {
		return configErr
	}
	if operatorConfigured {
		// Withdraw only our exact policy so an earlier-sorted administrator
		// config remains authoritative on the next boot as well as this pass.
		if configErr == nil {
			return os.Remove(memoryWatermarkFile)
		}
		return nil
	}
	if receipt.Version == 1 && receipt.BootID == strings.TrimSpace(string(boot)) && current != receipt.Target && current != receipt.Previous {
		return nil // Preserve a later administrator runtime decision.
	}
	if current <= target && receipt.Version == 0 {
		return nil
	}
	if current < target {
		return nil
	}
	if current == target && receipt.Target == target && configErr == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if receipt.Version == 0 || receipt.BootID != strings.TrimSpace(string(boot)) {
		receipt = memoryWatermarkReceipt{Version: 1, BootID: strings.TrimSpace(string(boot)), Previous: current, Target: target}
	} else {
		receipt.Target = target
	}
	data, err = json.Marshal(receipt)
	if err != nil {
		return err
	}
	if err = writeWatermarkFile(memoryWatermarkJournal, data, 0600); err != nil {
		return err
	}
	if err = os.WriteFile("/proc/sys/vm/min_free_kbytes", []byte(strconv.FormatInt(target, 10)), 0644); err != nil {
		return err
	}
	actual, err := os.ReadFile("/proc/sys/vm/min_free_kbytes")
	if err != nil || strings.TrimSpace(string(actual)) != strconv.FormatInt(target, 10) {
		return fmt.Errorf("memory reserve application not confirmed")
	}
	return writeWatermarkFile(memoryWatermarkFile, []byte(watermarkConfig(target)), 0644)
}
