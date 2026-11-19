//go:build linux

package memorybudget

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPhysicalMemoryParsing(t *testing.T) {
	if physicalBytes("MemTotal: 989368 kB\n") != 989368*1024 {
		t.Fatal("KiB conversion")
	}
	for _, bad := range []string{"MemTotal: -1 kB", "MemTotal: nonsense kB", "MemTotal: 99 MB", "MemTotal: 999999999999999999999 kB"} {
		if physicalBytes(bad) != 0 {
			t.Fatal("invalid memory accepted", bad)
		}
	}
}
func TestInheritedCgroupBudget(t *testing.T) {
	root := t.TempDir()
	leaf := filepath.Join(root, "system.slice", "agent.service")
	if err := os.MkdirAll(leaf, 0700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(leaf, "memory.max"), []byte("max\n"), 0600)
	os.WriteFile(filepath.Join(root, "system.slice", "memory.max"), []byte("536870912\n"), 0600)
	os.WriteFile(filepath.Join(root, "memory.max"), []byte("1073741824\n"), 0600)
	if inheritedCgroupLimit(root, "0::/system.slice/agent.service\n") != 536870912 {
		t.Fatal("inherited budget lost")
	}
	if inheritedCgroupLimit(root, "0::/../../outside\n") != 0 {
		t.Fatal("escaped cgroup accepted")
	}
	os.WriteFile(filepath.Join(leaf, "memory.max"), []byte("268435456\n"), 0600)
	if inheritedCgroupLimit(root, "0::/system.slice/agent.service\n") != 268435456 {
		t.Fatal("smallest ancestor did not win")
	}
}
