//go:build linux

package provisioning

import (
	"context"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestNativeSecurityPackageInventoryAndUpdate(t *testing.T) {
	if os.Getenv("INCUDAL_SYSINFO_COMPAT_TEST") != "disposable" {
		t.Skip("disposable Alpine root only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	world, err := os.ReadFile("/etc/apk/world")
	if err != nil {
		t.Fatal(err)
	}
	beforeOutput, err := run(ctx, "apk", "info", "-v")
	if err != nil {
		t.Fatal(err)
	}
	before, err := securityInstalledPackages(string(beforeOutput))
	if err != nil || len(before) == 0 {
		t.Fatal("actual apk inventory invalid", err)
	}
	if err = repairSecurityPackages(ctx); err != nil {
		t.Fatal("signed bounded leaf update", err)
	}
	afterOutput, err := run(ctx, "apk", "info", "-v")
	if err != nil {
		t.Fatal(err)
	}
	after, err := securityInstalledPackages(string(afterOutput))
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{}
	for _, name := range securityLeaves {
		allowed[name] = true
	}
	if len(before) != len(after) {
		t.Fatal("leaf update added or removed a package")
	}
	for name, version := range before {
		if after[name] != version && !allowed[name] {
			t.Fatal("unrelated installed package changed")
		}
	}
	currentWorld, err := os.ReadFile("/etc/apk/world")
	if err != nil || string(currentWorld) != string(world) {
		t.Fatal("administrator world constraints changed", err)
	}
	t.Log("PASS actual Alpine apk: complete installed inventory, signed leaf update and unrelated package preservation")
}

func TestSecurityPackageCompleteInventoryAndPinnedInstall(t *testing.T) {
	seen := map[string]bool{}
	for _, name := range securityLeaves {
		if seen[name] {
			t.Fatal("duplicate security target", name)
		}
		seen[name] = true
	}
	before, err := securityInstalledPackages("openssl-3.5.7-r0\nlibssl3-3.5.7-r0\nlinux-virt-6.12.1-r0\n")
	if err != nil || before["linux-virt"] != "6.12.1-r0" || before["libssl3"] != "3.5.7-r0" {
		t.Fatal(before, err)
	}
	for _, output := range []string{"openssl-3.5.7-r0\nopenssl-3.5.9-r0", "WARNING: ignored inventory", "invalid-package"} {
		if _, err := securityInstalledPackages(output); err == nil {
			t.Fatal("ambiguous inventory accepted")
		}
	}
	plan := "Upgrading openssl (3.5.7-r0 -> 3.5.9-r0)"
	expected := securityExpectedPackages(before, plan)
	if before["openssl"] != "3.5.7-r0" || expected["openssl"] != "3.5.9-r0" {
		t.Fatal("baseline mutated")
	}
	for _, delta := range []string{"openssl-3.5.9-r0\nlibssl3-3.5.7-r0", "openssl-3.5.9-r0\nlibssl3-3.5.9-r0\nlinux-virt-6.12.1-r0", "openssl-3.5.9-r0\nlibssl3-3.5.7-r0\nlinux-virt-6.12.1-r0\nextra-1.0-r0"} {
		after, err := securityInstalledPackages(delta)
		if err != nil || reflect.DeepEqual(expected, after) {
			t.Fatal("unreviewed install/removal/dependency accepted")
		}
	}
}

func TestSecurityPackagePlanRejectsUnrelatedRemovalAndMajorChange(t *testing.T) {
	before := map[string]string{"openssl": "3.5.7-r0", "curl": "8.16.0-r0"}
	if err := safeSecurityPackagePlan("(1/1) Upgrading openssl (3.5.7-r0 -> 3.5.9-r0)", before); err != nil {
		t.Fatal(err)
	}
	if err := safeSecurityPackagePlan("Upgrading lxc-libs (7.0.0-r0 -> 7.0.1-r0)\nUpgrading sqlite-libs (3.53.3-r0 -> 3.53.4-r0)", map[string]string{"lxc-libs": "7.0.0-r0", "sqlite-libs": "3.53.3-r0"}); err != nil {
		t.Fatal("actual daemon runtime dependencies excluded", err)
	}
	if err := safeSecurityPackagePlan("Upgrading musl (1.2.5-r0 -> 1.2.5-r1)", map[string]string{"musl": "1.2.5-r0"}); err == nil {
		t.Fatal("unreviewed libc maintenance allowed")
	}
	for _, output := range []string{"Removing openssl", "Upgrading openssl (4.0.0-r0)", "Upgrading linux-virt (6.20.1-r0)", "Installing unknown (1.0-r0)", "Downgrading curl (8.0-r0)", "UNTRUSTED"} {
		if safeSecurityPackagePlan(output, before) == nil {
			t.Fatal(output)
		}
	}
	for _, duplicate := range []string{
		"Upgrading openssl (3.5.7-r0 -> 3.5.9-r0)\nUpgrading openssl (3.5.7-r0 -> 3.5.9-r0)",
		"Upgrading openssl (3.5.7-r0 -> 3.5.9-r0)\nUpgrading openssl (3.5.7-r0 -> 3.5.10-r0)",
	} {
		if safeSecurityPackagePlan(duplicate, before) == nil {
			t.Fatal("repeated or conflicting package targets must be refused")
		}
	}
}
