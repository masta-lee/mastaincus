//go:build linux

package provisioning

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// musl cannot unload LXCFS's module safely. The original controller fence and
// a second all-projects local inventory must both prove an empty host before
// installing or activating these packages. A paid guest is never restarted.
var securityLxcfsTargets = append(append([]string{}, securityLeaves...), "lxcfs", "lxcfs-openrc", "fuse3-libs")

func authorizeEmptySecurityHost(ctx context.Context, permit *CompatPermit) error {
	if !validCompatPermit(permit) || len(permit.Guests) != 0 {
		return fmt.Errorf("LXCFS security maintenance waits for empty host authority")
	}
	raw, err := run(ctx, "incus", "query", "/1.0/instances?recursion=1&all-projects=true")
	if err != nil {
		return err
	}
	var guests []json.RawMessage
	if json.Unmarshal(raw, &guests) != nil || guests == nil || len(guests) != 0 {
		return fmt.Errorf("LXCFS security maintenance host is occupied or inventory unavailable")
	}
	raw, err = run(ctx, "incus", "query", "--raw", "/1.0/operations?recursion=1")
	if err != nil || !compatOperationsIdle(raw) {
		return fmt.Errorf("LXCFS security maintenance waits for host operations")
	}
	if !validCompatPermit(permit) {
		return fmt.Errorf("LXCFS security maintenance authority expired")
	}
	return nil
}

func repairLxcfsSecurity(ctx context.Context, permit *CompatPermit) error {
	if err := repairSecurityPackageSet(ctx, securityLxcfsTargets, func(ctx context.Context) error {
		return authorizeEmptySecurityHost(ctx, permit)
	}); err != nil {
		return err
	}
	unlock, err := lock()
	if err != nil {
		return err
	}
	defer unlock()
	if err := authorizeEmptySecurityHost(ctx, permit); err != nil {
		return err
	}
	// Always verify activation after a retry/restart: package versions alone
	// lose the fact that an earlier attempt stopped before loading its patch.
	pidPath, binaryPath := "/run/lxcfs.pid", "/usr/bin/lxcfs"
	hash, err := hashCompatFile(ctx, binaryPath)
	if err != nil {
		return err
	}
	pid, err := compatStartingDaemon(ctx, pidPath, binaryPath, hash)
	// A deleted running executable is the expected pending-patch case, but no
	// unknown PID may be stopped. Bind its original process and host namespace.
	if err != nil {
		pid, err = replacedLxcfsProcess(ctx, pidPath, binaryPath)
	}
	if err != nil {
		return err
	}
	if pid > 0 {
		old, err := securityProcessLoaded(ctx, "/proc", pid)
		if err != nil {
			return err
		}
		if !old {
			return ensureResourceVisibility(ctx)
		}
		if err := authorizeEmptySecurityHost(ctx, permit); err != nil {
			return err
		}
		// OpenRC's stop also unmounts FUSE. It is legal only with the exact
		// empty-host fence; never use this path for live customer mounts.
		if _, err := run(ctx, "rc-service", "lxcfs", "stop"); err != nil {
			return err
		}
	}
	if err := authorizeEmptySecurityHost(ctx, permit); err != nil {
		return err
	}
	if err := retireExitedCompatPID(ctx, pidPath, hash); err != nil {
		return err
	}
	if _, err := run(ctx, "rc-service", "lxcfs", "zap"); err != nil {
		return err
	}
	if err := ensureResourceVisibility(ctx); err != nil {
		return err
	}
	pid, err = compatStartingDaemon(ctx, pidPath, binaryPath, hash)
	if err != nil || pid < 2 {
		return fmt.Errorf("LXCFS security activation process not confirmed")
	}
	old, err := securityProcessLoaded(ctx, "/proc", pid)
	if err != nil || old {
		return fmt.Errorf("LXCFS security activation still pending")
	}
	return authorizeEmptySecurityHost(ctx, permit)
}

func replacedLxcfsProcess(ctx context.Context, pidPath, binaryPath string) (int, error) {
	// Do not weaken Incus's current-executable check to admit deleted binaries.
	// This separate empty-host path accepts only LXCFS's exact original path.
	info, err := os.Lstat(pidPath)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 32 || info.Mode()&0022 != 0 || info.Sys().(*syscall.Stat_t).Uid != 0 {
		return 0, fmt.Errorf("LXCFS original process receipt unsafe")
	}
	data, err := os.ReadFile(pidPath)
	if err != nil || len(data) > 32 {
		return 0, fmt.Errorf("LXCFS original process receipt unavailable")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid < 2 {
		return 0, fmt.Errorf("LXCFS original process receipt invalid")
	}
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil || exe != binaryPath+" (deleted)" {
		return 0, fmt.Errorf("LXCFS original executable identity changed")
	}
	if _, err := securityProcessLoaded(ctx, "/proc", pid); err != nil {
		return 0, err
	}
	start, err := compatProcessStart(pid)
	if err != nil {
		return 0, err
	}
	latestInfo, err := os.Lstat(pidPath)
	if err != nil || !os.SameFile(info, latestInfo) || info.ModTime() != latestInfo.ModTime() || info.Sys().(*syscall.Stat_t).Ctim != latestInfo.Sys().(*syscall.Stat_t).Ctim {
		return 0, fmt.Errorf("LXCFS original process receipt changed")
	}
	current, err := os.ReadFile(pidPath)
	after, startErr := compatProcessStart(pid)
	if err != nil || startErr != nil || string(current) != string(data) || start != after {
		return 0, fmt.Errorf("LXCFS original process changed")
	}
	return pid, nil
}
