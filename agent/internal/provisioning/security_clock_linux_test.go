//go:build linux

package provisioning

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNativeManagedHostClockSecurityActivation(t *testing.T) {
	if os.Getenv("INCUDAL_SYSINFO_COMPAT_TEST") != "disposable" || os.Getenv("INCUDAL_COMPAT_RELOAD_SCENARIO") != "empty-pool" {
		t.Skip("disposable empty Alpine clock only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	before, err := managedHostClockProcess(ctx)
	if err != nil {
		t.Fatal(err)
	}
	path := before.binary
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
	permit := &CompatPermit{RequestID: "11111111-1111-4111-8111-111111111111", HostIdentity: strings.Repeat("a", 64), ExpiresAt: time.Now().Add(240 * time.Second).Format(time.RFC3339Nano)}
	if err = repairHostClockSecurity(ctx, permit); err != nil {
		t.Fatal(err)
	}
	after, err := managedHostClockProcess(ctx)
	if err != nil || after.pending || after.pid == before.pid {
		t.Fatal("clock new process not verified", err)
	}
	idempotent, done := context.WithTimeout(context.Background(), 60*time.Second)
	defer done()
	if err = repairHostClockSecurity(idempotent, permit); err != nil {
		t.Fatal("idempotency", err)
	}
	t.Log("PASS managed Alpine chrony: exact empty-host authority, signed update, original slew configuration and new loaded process")
}

func TestNativeManagedHostClockStoppedRecovery(t *testing.T) {
	if os.Getenv("INCUDAL_SYSINFO_COMPAT_TEST") != "disposable" || os.Getenv("INCUDAL_COMPAT_RELOAD_SCENARIO") != "empty-pool" {
		t.Skip("disposable empty Alpine clock only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := run(ctx, "rc-service", "incudal-clock", "stop"); err != nil {
		t.Fatal(err)
	}
	if _, err := managedHostClockProcess(ctx); !errors.Is(err, errManagedClockStopped) {
		t.Fatal("exact stopped state not detected", err)
	}
	permit := &CompatPermit{RequestID: "11111111-1111-4111-8111-111111111111", HostIdentity: strings.Repeat("a", 64), ExpiresAt: time.Now().Add(120 * time.Second).Format(time.RFC3339Nano)}
	if err := repairHostClockSecurity(ctx, permit); err != nil {
		t.Fatal("stopped activation did not resume", err)
	}
	if after, err := managedHostClockProcess(ctx); err != nil || after.pid < 2 || after.pending {
		t.Fatal("restored managed clock not current", err)
	}
	t.Log("PASS stopped managed clock resumes with exact empty-host authority and current code")
}

func TestManagedClockFileRejectsUntrustedInputs(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned file validation")
	}
	root, err := os.MkdirTemp("/root", "security-clock-file-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	path := filepath.Join(root, "config")
	if err := os.WriteFile(path, []byte(managedClockConfiguration), 0600); err != nil {
		t.Fatal(err)
	}
	if data, err := readManagedClockFile(path); err != nil || string(data) != managedClockConfiguration {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readManagedClockFile(link); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := os.Link(path, filepath.Join(root, "hardlink")); err != nil {
		t.Fatal(err)
	}
	if _, err := readManagedClockFile(path); err == nil {
		t.Fatal("hardlink accepted")
	}
	if err := os.Remove(filepath.Join(root, "hardlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, make([]byte, 65537), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readManagedClockFile(path); err == nil {
		t.Fatal("oversize accepted")
	}
	if err := os.WriteFile(path, []byte("config"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := readManagedClockFile(path); err == nil {
		t.Fatal("writable file accepted")
	}
}
