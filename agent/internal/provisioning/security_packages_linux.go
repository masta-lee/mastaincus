//go:build linux

package provisioning

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Signed same-branch leaf packages only. Kernel, Incus, storage and service
// restarts stay under their separately validated maintenance recipes.
var securityLeaves = []string{"openssl", "libssl3", "libcrypto3", "curl", "libcurl", "ca-certificates"}
var securityPackageVersionChange = regexp.MustCompile(`(?m)Upgrading ([a-zA-Z0-9+_.-]+) \(([0-9][a-zA-Z0-9+_.~-]*) -> ([0-9][a-zA-Z0-9+_.~-]*)\)`)

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
	installed, err := run(ctx, "apk", "info", "-v")
	if err != nil {
		return err
	}
	before := map[string]string{}
	requested := []string{}
	for _, name := range securityLeaves {
		for _, line := range strings.Split(string(installed), "\n") {
			if strings.HasPrefix(line, name+"-") {
				version := strings.TrimPrefix(line, name+"-")
				if len(version) > 0 && version[0] >= '0' && version[0] <= '9' {
					before[name] = version
					requested = append(requested, name)
				}
			}
		}
	}
	if len(requested) == 0 {
		return nil
	}
	unlock, err := lock()
	if err != nil {
		return err
	}
	defer unlock()
	output, err := run(ctx, "apk", append([]string{"--simulate", "--no-cache", "--wait", "5", "upgrade"}, requested...)...)
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
		pinned = append(pinned, change[1]+"="+change[3])
	}
	if len(pinned) == 0 {
		return nil
	}
	if _, err = run(ctx, "apk", append([]string{"--no-cache", "--wait", "5", "add"}, pinned...)...); err != nil {
		return err
	}
	after, err := run(ctx, "apk", "info", "-v")
	if err != nil {
		return err
	}
	for _, change := range securityPackageVersionChange.FindAllStringSubmatch(string(output), -1) {
		if !strings.Contains("\n"+string(after)+"\n", "\n"+change[1]+"-"+change[3]+"\n") {
			return fmt.Errorf("security package installation not confirmed")
		}
	}
	return nil
}
