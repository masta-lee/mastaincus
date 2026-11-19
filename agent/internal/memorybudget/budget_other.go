//go:build !linux

package memorybudget

func availableBudget() (int64, int64) { return 0, 0 }
