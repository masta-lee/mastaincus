// Installed only in the fixed-source Incus daemon build, never guest images.
package main

import (
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
)

func incudalDaemonMemoryBudget(meminfo string, cgroup int64) int64 {
	for _, line := range strings.Split(meminfo, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[0] != "MemTotal:" || fields[2] != "kB" {
			continue
		}
		kb, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || kb <= 0 || kb > 1<<40 {
			return 0
		}
		// Headroom is for Go-managed daemon memory only; native libraries,
		// executable mappings and the customer quota are not constrained.
		capacity := kb * 1024
		if cgroup > 0 && cgroup < capacity {
			capacity = cgroup
		}
		budget := capacity / 24
		if budget < 48<<20 {
			budget = 48 << 20
		}
		if budget > 256<<20 {
			budget = 256 << 20
		}
		return budget
	}
	return 0
}

func incudalDaemonCgroupLimit(root, groups string) int64 {
	var limit int64
	for _, line := range strings.Split(groups, "\n") {
		if !strings.HasPrefix(line, "0::/") {
			continue
		}
		leaf := filepath.Clean(root + strings.TrimPrefix(line, "0::"))
		if leaf != root && !strings.HasPrefix(leaf, root+string(os.PathSeparator)) {
			continue
		}
		for dir := leaf; ; dir = filepath.Dir(dir) {
			data, err := os.ReadFile(filepath.Join(dir, "memory.max"))
			if err == nil {
				if n, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64); err == nil && n > 0 && (limit == 0 || n < limit) {
					limit = n
				}
			}
			if dir == root {
				break
			}
		}
	}
	return limit
}

func incudalConfigureDaemonMemory() {
	if strings.TrimSpace(os.Getenv("GOMEMLIMIT")) != "" {
		return
	}
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return
	}
	groups, _ := os.ReadFile("/proc/self/cgroup")
	if budget := incudalDaemonMemoryBudget(string(data), incudalDaemonCgroupLimit("/sys/fs/cgroup", string(groups))); budget > 0 {
		debug.SetMemoryLimit(budget)
	}
}
