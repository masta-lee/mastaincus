//go:build linux

package provisioning

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestLxcfsSecurityRejectsOccupiedOrExpiredAuthority(t *testing.T) {
	p := &CompatPermit{RequestID: "11111111-1111-4111-8111-111111111111", HostIdentity: strings.Repeat("a", 64), ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339Nano), Guests: []CompatGuestPermit{{Name: "paid", UUID: "11111111-1111-4111-8111-111111111111", State: "Running"}}}
	if err := authorizeEmptySecurityHost(context.Background(), p); err == nil {
		t.Fatal("customer-bearing permit allowed a FUSE interruption")
	}
	p.Guests = nil
	p.ExpiresAt = time.Now().Add(-time.Minute).Format(time.RFC3339Nano)
	if err := authorizeEmptySecurityHost(context.Background(), p); err == nil {
		t.Fatal("expired empty-host authority accepted")
	}
	before := map[string]string{"lxcfs": "6.0.1-r0", "lxcfs-openrc": "6.0.1-r0", "fuse3-libs": "3.18.0-r0"}
	plan := "Upgrading lxcfs (6.0.1-r0 -> 6.0.1-r1)\nUpgrading lxcfs-openrc (6.0.1-r0 -> 6.0.1-r1)"
	if safeSecurityPackagePlan(plan, before) == nil {
		t.Fatal("live-host leaf updater was allowed to change LXCFS")
	}
	if err := safeSecurityPackagePlanFor(plan, before, securityLxcfsTargets); err != nil {
		t.Fatal("empty-host reviewed patch plan refused", err)
	}
}

func TestLxcfsOriginalDeletedExecutableReceipt(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root process evidence required")
	}
	root := t.TempDir()
	binary, pidPath := filepath.Join(root, "lxcfs"), filepath.Join(root, "lxcfs.pid")
	data, err := os.ReadFile("/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(binary, data, 0755); err != nil {
		t.Fatal(err)
	}
	process := exec.Command(binary, "30")
	process.Args[0] = "sleep"
	if err = process.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = process.Process.Kill(); _ = process.Wait() }()
	if err = os.WriteFile(pidPath, []byte(strconv.Itoa(process.Process.Pid)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = replacedLxcfsProcess(context.Background(), pidPath, binary); err == nil {
		t.Fatal("unchanged executable accepted as deleted original")
	}
	if err = os.WriteFile(binary+".new", data, 0755); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(binary+".new", binary); err != nil {
		t.Fatal(err)
	}
	if pid, err := replacedLxcfsProcess(context.Background(), pidPath, binary); err != nil || pid != process.Process.Pid {
		t.Fatal("same original process lost after package replaced its file", pid, err)
	}
	if _, err = replacedLxcfsProcess(context.Background(), pidPath, binary+".wrong"); err == nil {
		t.Fatal("other service accepted")
	}
	for _, value := range []string{fmt.Sprint(process.Process.Pid) + " extra", "1", "invalid"} {
		os.WriteFile(pidPath, []byte(value), 0600)
		if _, err = replacedLxcfsProcess(context.Background(), pidPath, binary); err == nil {
			t.Fatal("ambiguous process identity accepted")
		}
	}
	os.WriteFile(pidPath, []byte(strconv.Itoa(process.Process.Pid)), 0600)
	os.Chmod(pidPath, 0666)
	if _, err = replacedLxcfsProcess(context.Background(), pidPath, binary); err == nil {
		t.Fatal("writable PID identity accepted")
	}
}

func TestNativeLxcfsEmptyHostSecurityActivation(t *testing.T) {
	if os.Getenv("INCUDAL_SYSINFO_COMPAT_TEST") != "disposable" || os.Getenv("INCUDAL_COMPAT_RELOAD_SCENARIO") != "empty-pool" {
		t.Skip("disposable empty Alpine host only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	p := &CompatPermit{RequestID: "11111111-1111-4111-8111-111111111111", HostIdentity: strings.Repeat("a", 64), ExpiresAt: time.Now().Add(240 * time.Second).Format(time.RFC3339Nano)}
	for {
		if err := authorizeEmptySecurityHost(ctx, p); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("fixture startup operations did not settle")
		case <-time.After(time.Second):
		}
	}
	if err := repair(ctx); err != nil {
		// Fixed commands inside this disposable root only; no customer config
		// or credentials are printed when native package/tool startup fails.
		for _, tool := range required {
			flag := "--help"
			if tool == "unsquashfs" {
				flag = "-version"
			}
			output, probeErr := run(ctx, tool, flag)
			t.Logf("fixture tool %s exit=%v bytes=%d", tool, probeErr, len(output))
		}
		output, probeErr := run(ctx, "apk", "info", "-v", "lxcfs", "lxcfs-openrc", "apparmor-utils")
		t.Logf("fixture required package inventory: %s exit=%v", output, probeErr)
		t.Fatal(err)
	}
	t.Log("fixture host tools ready")
	if err := ensureResourceVisibility(ctx); err != nil {
		for _, action := range []string{"status", "start"} {
			output, probeErr := run(ctx, "rc-service", "lxcfs", action)
			t.Logf("fixture LXCFS %s: %s exit=%v", action, output, probeErr)
		}
		t.Fatal(err)
	}
	t.Log("fixture original LXCFS active")
	path := "/usr/bin/lxcfs"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path+".security-test", data, 0755); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(path+".security-test", path); err != nil {
		t.Fatal(err)
	}
	activate, done := context.WithTimeout(ctx, 60*time.Second)
	err = repairLxcfsSecurity(activate, p)
	done()
	if err != nil {
		t.Fatal("activate original empty-host FUSE service after executable replacement", err)
	}
	t.Log("fixture replaced original LXCFS activated within product deadline")
	activate, done = context.WithTimeout(ctx, 60*time.Second)
	err = repairLxcfsSecurity(activate, p)
	done()
	if err != nil {
		t.Fatal("idempotent activation", err)
	}
	t.Log("PASS Alpine LXCFS: exact empty-host authority, signed package transaction, replaced original executable activation and idempotency")
}
