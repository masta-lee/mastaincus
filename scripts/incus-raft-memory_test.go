package cluster

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIncudalStandaloneRaftMemory(t *testing.T) {
	for _, tc := range []struct {
		address, meminfo string
		cgroup           int64
		want             bool
	}{
		{"1", "MemTotal: 989376 kB", 0, true},
		{"1", "MemTotal: 2097152 kB", 0, true},
		{"1", "MemTotal: 2097153 kB", 0, false},
		{"1", "MemTotal: 16777216 kB", 966 << 20, true},
		{"10.0.0.2:8443", "MemTotal: 989376 kB", 0, false},
		{"", "MemTotal: 989376 kB", 0, false},
		{"1", "MemTotal: -1 kB", 0, false},
		{"1", "MemTotal: 512 MB", 0, false},
	} {
		if got := incudalStandaloneRaftMemory(tc.address, tc.meminfo, tc.cgroup); got != tc.want {
			t.Fatalf("%+v: %v", tc, got)
		}
	}
	root := t.TempDir()
	leaf := filepath.Join(root, "host", "daemon")
	if err := os.MkdirAll(leaf, 0700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(root, "memory.max"), []byte("1012924416"), 0600)
	os.WriteFile(filepath.Join(leaf, "memory.max"), []byte("max"), 0600)
	if incudalRaftCgroupLimit(root, "0::/host/daemon\n") != 966<<20 {
		t.Fatal("ancestor limit lost")
	}
	if incudalRaftCgroupLimit(root, "0::/../../outside\n") != 0 {
		t.Fatal("escaped path accepted")
	}
}
