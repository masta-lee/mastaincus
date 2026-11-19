package memorybudget

import (
	"runtime/debug"
	"testing"
)

func TestAgentBudgetUsesPhysicalAndParentLimit(t *testing.T) {
	for _, test := range []struct{ physical, cgroup, want int64 }{
		{0, 0, 0}, {966 << 20, 0, (966 << 20) / 16}, {6 << 30, 0, 256 << 20},
		{1 << 30, 512 << 20, 32 << 20}, {6 << 30, 1 << 30, 64 << 20}, {1 << 30, 8 << 30, 64 << 20},
	} {
		if got := budgetFor(test.physical, test.cgroup); got != test.want {
			t.Fatalf("%+v: got %d", test, got)
		}
	}
}
func TestExplicitOperatorLimitIsPreserved(t *testing.T) {
	before := debug.SetMemoryLimit(-1)
	defer debug.SetMemoryLimit(before)
	debug.SetMemoryLimit(80 << 20)
	t.Setenv("GOMEMLIMIT", "80MiB")
	if Configure() != 80<<20 || debug.SetMemoryLimit(-1) != 80<<20 {
		t.Fatal("operator limit replaced")
	}
}
