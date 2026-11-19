package main

import (
	"os"
	"path/filepath"
	"runtime/debug"
	"testing"
)

func TestIncudalDaemonMemoryBudget(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  int64
	}{
		{"MemTotal: 989376 kB\n", 48 << 20},
		{"MemTotal: 6291456 kB\n", 256 << 20},
		{"MemTotal: 3145728 kB\n", 128 << 20},
		{"MemTotal: -1 kB\n", 0}, {"MemTotal: 1 MB", 0}, {"malformed", 0},
	} {
		if got := incudalDaemonMemoryBudget(tc.input, 0); got != tc.want {
			t.Fatalf("%s: got %d want %d", tc.input, got, tc.want)
		}
	}
	if got := incudalDaemonMemoryBudget("MemTotal: 16777216 kB\n", 966<<20); got != 48<<20 {
		t.Fatal("daemon ignores inherited small-host cgroup", got)
	}
	root := t.TempDir()
	leaf := filepath.Join(root, "host", "daemon")
	if err := os.MkdirAll(leaf, 0700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(root, "host", "memory.max"), []byte("1012924416"), 0600)
	os.WriteFile(filepath.Join(leaf, "memory.max"), []byte("max"), 0600)
	if incudalDaemonCgroupLimit(root, "0::/host/daemon\n") != 966<<20 {
		t.Fatal("ancestor limit lost")
	}
	if incudalDaemonCgroupLimit(root, "0::/../../escape\n") != 0 {
		t.Fatal("escaped cgroup accepted")
	}
	old := debug.SetMemoryLimit(-1)
	defer debug.SetMemoryLimit(old)
	debug.SetMemoryLimit(90 << 20)
	t.Setenv("GOMEMLIMIT", "90MiB")
	incudalConfigureDaemonMemory()
	if debug.SetMemoryLimit(-1) != 90<<20 {
		t.Fatal("explicit daemon operator setting overwritten")
	}
}
