//go:build linux

package provisioning

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

var debianToolPackage = regexp.MustCompile(`^[a-z0-9+.-]+:(amd64|arm64|all)$`)
var debianToolVersion = regexp.MustCompile(`^[0-9][a-zA-Z0-9+_.:~-]*$`)

func debianToolInventory(ctx context.Context) (map[string]string, error) {
	output, err := run(ctx, "dpkg-query", "-W", "-f=${Package}:${Architecture}\t${db:Status-Status}\t${Version}\n")
	if err != nil {
		return nil, err
	}
	return parseDebianToolInventory(string(output))
}

func parseDebianToolInventory(output string) (map[string]string, error) {
	packages := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) != 3 || !debianToolPackage.MatchString(fields[0]) || !debianToolVersion.MatchString(fields[2]) {
			return nil, fmt.Errorf("tool package inventory invalid")
		}
		if fields[1] != "installed" {
			continue
		}
		if packages[fields[0]] != "" || len(packages) >= 8192 {
			return nil, fmt.Errorf("tool package inventory ambiguous or excessive")
		}
		packages[fields[0]] = fields[2]
	}
	return packages, nil
}

func expectedDebianTools(before map[string]string, plan string) (map[string]string, error) {
	if err := safePlan(plan, false); err != nil {
		return nil, err
	}
	expected := map[string]string{}
	for name, version := range before {
		expected[name] = version
	}
	seen := map[string]bool{}
	for _, change := range aptVersion.FindAllStringSubmatch(plan, -1) {
		name, version := change[1], change[2]
		matches := []string{}
		for identity := range before {
			if identity == name || !strings.Contains(name, ":") && strings.Split(identity, ":")[0] == name {
				matches = append(matches, identity)
			}
		}
		identity := name
		if len(matches) == 1 {
			identity = matches[0]
			if version != before[identity] {
				return nil, fmt.Errorf("tool preparation cannot change existing package versions")
			}
		} else if len(matches) > 1 {
			return nil, fmt.Errorf("tool package architecture ambiguous")
		} else if !strings.Contains(name, ":") {
			// Install plan architecture appears at the end of its origin tuple.
			row := regexp.MustCompile(`(?m)^Inst ` + regexp.QuoteMeta(name) + `[^\n]*\[(amd64|arm64|all)\]\)`)
			architecture := row.FindStringSubmatch(plan)
			if architecture == nil {
				return nil, fmt.Errorf("new tool dependency architecture unavailable")
			}
			identity = name + ":" + architecture[1]
		}
		if seen[identity] || !debianToolPackage.MatchString(identity) {
			return nil, fmt.Errorf("tool package plan repeats or changes identity")
		}
		seen[identity] = true
		expected[identity] = version
	}
	if strings.Count(plan, "Inst ") != len(seen) {
		return nil, fmt.Errorf("tool package plan not completely parsed")
	}
	return expected, nil
}
