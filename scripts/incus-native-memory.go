package main

/*
#include <sys/prctl.h>
#include <stdio.h>
#include <string.h>
static int incudal_set_daemon_thp(int disabled) {
    return prctl(PR_SET_THP_DISABLE, disabled, 0, 0, 0);
}
*/
import "C"

import (
	"os"
	"strings"
)

func incudalNativeMemoryDefault() {
	// A daemon-local setting, never a kernel/global or customer cgroup policy.
	// Respect an explicit operator decision. Helpers reset inheritance in the
	// existing pre-Go namespace constructor before starting any customer code.
	var explicit string
	for _, field := range strings.Split(os.Getenv("GODEBUG"), ",") {
		if strings.HasPrefix(field, "disablethp=") {
			explicit = strings.TrimPrefix(field, "disablethp=")
		}
	}
	if explicit == "0" {
		return
	}
	mem, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return
	}
	groups, _ := os.ReadFile("/proc/self/cgroup")
	budget := incudalDaemonMemoryBudget(string(mem), incudalDaemonCgroupLimit("/sys/fs/cgroup", string(groups)))
	if budget == 0 || budget > (2<<30)/24 {
		return
	}
	if C.incudal_set_daemon_thp(1) != 0 {
		// Unsupported kernels keep their working daemon; Go budget still applies.
		return
	}
}
