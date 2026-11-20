// Applied only to standalone small-memory Incus nodes. Cluster retention and
// durable database/raft formats stay unchanged; cowsql performs safe compaction.
package cluster

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	cowsql "github.com/cowsql/go-cowsql"
)

func incudalStandaloneRaftMemory(address, meminfo string, cgroup int64) bool {
	if address != "1" {
		return false
	}
	for _, line := range strings.Split(meminfo, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[0] != "MemTotal:" || fields[2] != "kB" {
			continue
		}
		kb, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || kb <= 0 || kb > 1<<40 {
			return false
		}
		capacity := kb * 1024
		if cgroup > 0 && cgroup < capacity {
			capacity = cgroup
		}
		return capacity <= 2<<30
	}
	return false
}

func incudalRaftCgroupLimit(root, groups string) int64 {
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

func incudalStandaloneRaftOption(address string) cowsql.Option {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return nil
	}
	groups, _ := os.ReadFile("/proc/self/cgroup")
	limit := incudalRaftCgroupLimit("/sys/fs/cgroup", string(groups))
	if !incudalStandaloneRaftMemory(address, string(data), limit) {
		return nil
	}
	// Keep the original 1024-entry snapshot cadence, and at least a full
	// cadence of trailing entries. cowsql requires trailing >= threshold so
	// the second-last snapshot remains recoverable. No files are removed here.
	return cowsql.WithSnapshotParams(cowsql.SnapshotParams{Threshold: 1024, Trailing: 1024})
}
