//go:build linux

package provisioning

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
)

// Signed same-branch leaf packages only. Kernel, Incus, storage and service
// restarts stay under their separately validated maintenance recipes.
var securityLeaves = []string{"openssl", "libssl3", "libcrypto3", "curl", "libcurl", "ca-certificates",
	"lxc", "lxc-libs", "sqlite-libs", "libseccomp", "libcap2", "acl-libs", "libattr", "libuv", "lz4-libs", "zstd-libs", "xz-libs", "libintl", "libgcc",
	"tar", "gzip", "xz", "squashfs-tools", "rsync", "libpsl", "libidn2", "libunistring", "c-ares", "brotli-libs", "nghttp2-libs"}
var securityPackageVersionChange = regexp.MustCompile(`(?m)Upgrading ([a-zA-Z0-9+_.-]+) \(([0-9][a-zA-Z0-9+_.~-]*) -> ([0-9][a-zA-Z0-9+_.~-]*)\)`)
var installedSecurityPackage = regexp.MustCompile(`^([a-zA-Z0-9+_.-]+)-([0-9][a-zA-Z0-9+_.~-]*)$`)

func securityInstalledPackages(output string) (map[string]string, error) {
	packages := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line == "" {
			continue
		}
		match := installedSecurityPackage.FindStringSubmatch(line)
		if match == nil || packages[match[1]] != "" || len(packages) >= 8192 {
			return nil, fmt.Errorf("security package inventory invalid")
		}
		packages[match[1]] = match[2]
	}
	return packages, nil
}
func securityExpectedPackages(before map[string]string, plan string) map[string]string {
	expected := map[string]string{}
	for name, version := range before {
		expected[name] = version
	}
	for _, change := range securityPackageVersionChange.FindAllStringSubmatch(plan, -1) {
		expected[change[1]] = change[3]
	}
	return expected
}

func safeSecurityPackagePlan(output string, before map[string]string) error {
	if strings.Contains(output, "Removing ") || strings.Contains(output, "Downgrading ") || strings.Contains(output, "UNTRUSTED") {
		return fmt.Errorf("security package plan refused")
	}
	if strings.Contains(output, "Installing ") || strings.Contains(output, "Reinstalling ") {
		return fmt.Errorf("unexpected security package installation refused")
	}
	allowed := map[string]bool{}
	seen := map[string]bool{}
	for _, name := range securityLeaves {
		allowed[name] = true
	}
	for _, change := range securityPackageVersionChange.FindAllStringSubmatch(output, -1) {
		old, ok := before[change[1]]
		if !ok || !allowed[change[1]] || seen[change[1]] || old != change[2] || strings.Split(old, ".")[0] != strings.Split(change[3], ".")[0] {
			return fmt.Errorf("unreviewed security package change refused")
		}
		seen[change[1]] = true
	}
	if strings.Count(output, "Upgrading ") != len(securityPackageVersionChange.FindAllStringSubmatch(output, -1)) {
		return fmt.Errorf("unknown security package plan format")
	}
	return nil
}
func repairSecurityPackages(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("security package update requires root")
	}
	release, err := os.ReadFile("/etc/alpine-release")
	if err != nil {
		return fmt.Errorf("security package distribution needs reviewed update")
	}
	parts := strings.Split(strings.TrimSpace(string(release)), ".")
	if len(parts) < 2 || !regexp.MustCompile(`^3\.(22|23|24)$`).MatchString(strings.Join(parts[:2], ".")) {
		return fmt.Errorf("security package branch unsupported")
	}
	repositories, err := os.ReadFile("/etc/apk/repositories")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(repositories), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		base := "https://dl-cdn.alpinelinux.org/alpine/v" + strings.Join(parts[:2], ".") + "/"
		if line != base+"main" && line != base+"community" {
			return fmt.Errorf("security package repository needs reviewed update")
		}
	}
	unlock, err := lock()
	if err != nil {
		return err
	}
	defer unlock()
	installed, err := run(ctx, "apk", "info", "-v")
	if err != nil {
		return err
	}
	before, err := securityInstalledPackages(string(installed))
	if err != nil {
		return err
	}
	requested := []string{}
	for _, name := range securityLeaves {
		if before[name] != "" {
			requested = append(requested, name)
		}
	}
	if len(requested) == 0 {
		return nil
	}
	// All stages reuse one root-private cache and the same signed index. Repeated
	// --no-cache downloads waste the bounded repair window on slow small hosts.
	cache, err := os.MkdirTemp("/var/lib/incudal-agent", ".security-packages-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(cache)
	if filepath.Dir(cache) != "/var/lib/incudal-agent" {
		return fmt.Errorf("security package cache invalid")
	}
	base := []string{"--cache-dir", cache, "--cache-max-age", "60", "--wait", "5", "--timeout", "15"}
	// apk --simulate intentionally never writes missing indexes, even with
	// --update-cache. Fetch and verify them explicitly once before simulation.
	if _, err = run(ctx, "apk", append(append([]string{}, base...), "update")...); err != nil {
		return err
	}
	output, err := run(ctx, "apk", append(append([]string{}, base...), append([]string{"--simulate", "upgrade"}, requested...)...)...)
	if err != nil {
		return err
	}
	if err = safeSecurityPackagePlan(string(output), before); err != nil {
		return err
	}
	pinned := []string{}
	for _, change := range securityPackageVersionChange.FindAllStringSubmatch(string(output), -1) {
		order, err := run(ctx, "apk", "version", "--test", change[2], change[3])
		if err != nil || strings.TrimSpace(string(order)) != "<" {
			return fmt.Errorf("security package version order refused")
		}
		pinned = append(pinned, change[1])
	}
	if len(pinned) == 0 {
		return nil
	}
	// Exact add atoms would persist in /etc/apk/world and block the next patch.
	// upgrade accepts package names. The same verified cached index and complete
	// second plan bind their exact versions without modifying world constraints.
	// Package names still let apk solve dependencies. Re-simulate the upgrade
	// transaction and require the original complete installed baseline before
	// mutation; no extra dependency or unrelated package change is authorized.
	current, err := run(ctx, "apk", "info", "-v")
	if err != nil {
		return err
	}
	currentPackages, err := securityInstalledPackages(string(current))
	if err != nil || !reflect.DeepEqual(currentPackages, before) {
		return fmt.Errorf("security package baseline changed")
	}
	actualPlan, err := run(ctx, "apk", append(append([]string{}, base...), append([]string{"--simulate", "upgrade"}, pinned...)...)...)
	if err != nil {
		return err
	}
	if err = safeSecurityPackagePlan(string(actualPlan), before); err != nil {
		return err
	}
	expected := securityExpectedPackages(before, string(output))
	if !reflect.DeepEqual(expected, securityExpectedPackages(before, string(actualPlan))) {
		return fmt.Errorf("security package install plan changed")
	}
	if _, err = run(ctx, "apk", append(append([]string{}, base...), append([]string{"upgrade"}, pinned...)...)...); err != nil {
		return err
	}
	after, err := run(ctx, "apk", "info", "-v")
	if err != nil {
		return err
	}
	afterPackages, err := securityInstalledPackages(string(after))
	if err != nil || !reflect.DeepEqual(expected, afterPackages) {
		return fmt.Errorf("security package installation not confirmed")
	}
	return nil
}
