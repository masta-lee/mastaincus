// Package memorybudget bounds only the Agent's Go-managed memory. Kernel and
// customer cgroups are never changed, and an explicit operator limit wins.
package memorybudget

import (
	"os"
	"runtime/debug"
	"strings"
)

const minBudget = int64(32 << 20)
const maxBudget = int64(256 << 20)

func budgetFor(physical, cgroup int64) int64 {
	if physical <= 0 {
		return 0
	}
	if cgroup > 0 && cgroup < physical {
		physical = cgroup
	}
	budget := physical / 16
	if budget < minBudget {
		budget = minBudget
	}
	if budget > maxBudget {
		budget = maxBudget
	}
	return budget
}

// Applied on every normal Agent startup, including new installs and upgrades.
// SetMemoryLimit is a GC/scavenger target, never an OOM-inducing service limit.
func Configure() int64 {
	if strings.TrimSpace(os.Getenv("GOMEMLIMIT")) != "" {
		return debug.SetMemoryLimit(-1)
	}
	physical, cgroup := availableBudget()
	budget := budgetFor(physical, cgroup)
	if budget > 0 {
		debug.SetMemoryLimit(budget)
	}
	return budget
}
