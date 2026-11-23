//go:build linux

package provisioning

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strings"
)

func alpineToolExpected(before map[string]string, plan string) (map[string]string, error) {
	if strings.Contains(plan, "Upgrading ") {
		return nil, fmt.Errorf("tool preparation cannot upgrade installed runtime")
	}
	if err := safePlan(plan, true); err != nil {
		return nil, err
	}
	expected := securityExpectedPackages(before, plan)
	seen := map[string]bool{}
	for _, change := range securityPackageVersionChange.FindAllStringSubmatch(plan, -1) {
		if before[change[1]] != change[2] || seen[change[1]] {
			return nil, fmt.Errorf("tool package baseline invalid")
		}
		seen[change[1]] = true
	}
	for _, change := range apkChange.FindAllStringSubmatch(plan, -1) {
		name, version := change[2], change[3]
		if seen[name] || change[1] == "Downgrading" || (change[1] == "Installing") != (before[name] == "") {
			return nil, fmt.Errorf("tool package plan conflicts with baseline")
		}
		seen[name] = true
		if change[1] == "Reinstalling" && before[name] != version {
			return nil, fmt.Errorf("tool repair version changed during reinstall")
		}
		expected[name] = version
	}
	count := 0
	for _, action := range []string{"Installing ", "Upgrading ", "Reinstalling ", "Downgrading "} {
		count += strings.Count(plan, action)
	}
	if count != len(seen) {
		return nil, fmt.Errorf("tool package plan not completely parsed")
	}
	return expected, nil
}

func alpineToolWorldPreserved(before, after string, requested []string, adding bool) bool {
	constraints := func(text string) map[string]bool {
		values := map[string]bool{}
		for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
			if line != "" {
				values[line] = true
			}
		}
		return values
	}
	expected := constraints(before)
	if adding {
		for _, name := range requested {
			found := false
			for line := range expected {
				end := strings.IndexAny(line, "@=~<>")
				base := line
				if end >= 0 {
					base = line[:end]
				}
				if base == name {
					found = true
				}
			}
			if !found {
				expected[name] = true
			}
		}
	}
	return reflect.DeepEqual(expected, constraints(after))
}

// apk add name=version persists exact constraints, including dependencies,
// blocking later security revisions. Bind the transaction to a single signed
// cached index and two complete plans instead; retain administrator constraints.
func repairAlpineTools(ctx context.Context, packages []string) error {
	output, err := run(ctx, "apk", "info", "-v")
	if err != nil {
		return err
	}
	before, err := securityInstalledPackages(string(output))
	if err != nil {
		return err
	}
	world, err := os.ReadFile("/etc/apk/world")
	if err != nil {
		return err
	}
	cache, err := os.MkdirTemp("/var/lib/incudal-agent", ".tool-packages-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(cache)
	base := []string{"--cache-dir", cache, "--cache-max-age", "60", "--wait", "5", "--timeout", "15"}
	if _, err := run(ctx, "apk", append(append([]string{}, base...), "update")...); err != nil {
		return err
	}
	requested := []string{}
	for _, name := range packages {
		if before[name] == "" {
			requested = append(requested, name)
		}
	}
	action := "add"
	if len(requested) == 0 {
		action = "fix"
		requested = packages
	}
	// An administrator may deliberately constrain an absent package too.
	// Refuse before mutation rather than overwriting that existing constraint.
	if action == "add" {
		for _, name := range requested {
			for _, line := range strings.Split(string(world), "\n") {
				if strings.HasPrefix(line, name+"=") || strings.HasPrefix(line, name+"~") || strings.HasPrefix(line, name+"<") || strings.HasPrefix(line, name+">") || strings.HasPrefix(line, name+"@") {
					return fmt.Errorf("tool repair absent package is administrator constrained")
				}
			}
		}
	}
	query := func() ([]byte, error) {
		return run(ctx, "apk", append(append([]string{}, base...), append([]string{"--simulate", action}, requested...)...)...)
	}
	plan, err := query()
	if err != nil {
		return err
	}
	expected, err := alpineToolExpected(before, string(plan))
	if err != nil {
		return err
	}
	if reflect.DeepEqual(expected, before) && !strings.Contains(string(plan), "Reinstalling ") {
		return fmt.Errorf("tool repair plan unavailable")
	}
	if action == "add" {
		for name, version := range before {
			if expected[name] != version {
				return fmt.Errorf("tool installation cannot update existing runtime")
			}
		}
	}
	current, err := run(ctx, "apk", "info", "-v")
	if err != nil {
		return err
	}
	currentPackages, err := securityInstalledPackages(string(current))
	if err != nil || !reflect.DeepEqual(before, currentPackages) {
		return fmt.Errorf("tool repair baseline changed")
	}
	actual, err := query()
	if err != nil {
		return err
	}
	actualExpected, err := alpineToolExpected(before, string(actual))
	if err != nil || !reflect.DeepEqual(expected, actualExpected) {
		return fmt.Errorf("tool repair install plan changed")
	}
	if _, err := run(ctx, "apk", append(append([]string{}, base...), append([]string{action}, requested...)...)...); err != nil {
		return err
	}
	after, err := run(ctx, "apk", "info", "-v")
	if err != nil {
		return err
	}
	afterPackages, err := securityInstalledPackages(string(after))
	if err != nil || !reflect.DeepEqual(expected, afterPackages) {
		return fmt.Errorf("tool repair complete installation not confirmed")
	}
	currentWorld, err := os.ReadFile("/etc/apk/world")
	if err != nil || !alpineToolWorldPreserved(string(world), string(currentWorld), requested, action == "add") {
		return fmt.Errorf("tool repair administrator package constraints changed")
	}
	return nil
}
