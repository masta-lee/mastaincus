//go:build linux

package memorybudget

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func physicalBytes(data string) int64 {
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "MemTotal:" && fields[2] == "kB" {
			v, err := strconv.ParseInt(fields[1], 10, 64)
			if err == nil && v > 0 && v <= 1<<50 {
				return v * 1024
			}
		}
	}
	return 0
}

func availableBudget() (int64, int64) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	physical := physicalBytes(string(data))
	// Read all cgroup-v2 ancestors: a unit's "max" may inherit a parent limit.
	groups, _ := os.ReadFile("/proc/self/cgroup")
	return physical, inheritedCgroupLimit("/sys/fs/cgroup", string(groups))
}

func inheritedCgroupLimit(root, groups string) int64 {
	var cgroup int64
	for _, line := range strings.Split(string(groups), "\n") {
		if !strings.HasPrefix(line, "0::/") {
			continue
		}
		leaf := filepath.Clean(root + strings.TrimPrefix(line, "0::"))
		if leaf != root && !strings.HasPrefix(leaf, root+string(os.PathSeparator)) {
			continue
		}
		for current := leaf; ; current = filepath.Dir(current) {
			raw, e := os.ReadFile(filepath.Join(current, "memory.max"))
			if e == nil {
				if n, e := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64); e == nil && n > 0 && (cgroup == 0 || n < cgroup) {
					cgroup = n
				}
			}
			if current == root {
				break
			}
		}
	}
	return cgroup
}
