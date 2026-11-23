//go:build linux

package provisioning

import (
	"reflect"
	"testing"
)

func TestAlpineToolCompletePlanAndAdministratorWorld(t *testing.T) {
	before := map[string]string{"curl": "8.16.0-r0", "lxcfs": "6.0.1-r0", "tar": "1.35-r0"}
	plan := "Installing gzip (1.15-r0)\nInstalling zlib (1.3.1-r2)"
	after, err := alpineToolExpected(before, plan)
	if err != nil || after["gzip"] != "1.15-r0" || after["curl"] != before["curl"] || before["gzip"] != "" {
		t.Fatal("complete immutable tool baseline", after, err)
	}
	for _, plan := range []string{"Upgrading curl (8.16.0-r0 -> 8.17.0-r0)", "Installing curl (8.17.0-r0)", "Removing tar", "Reinstalling tar (1.36-r0)", "Installing gzip (1.15-r0)\nInstalling gzip (1.15-r0)", "Upgrading unknown (1.0-r0 -> 1.1-r0)", "Upgrading tar (unknown)"} {
		if _, err := alpineToolExpected(before, plan); err == nil {
			t.Fatal("ambiguous/expanded/different installed plan accepted", plan)
		}
	}
	after, err = alpineToolExpected(before, "Reinstalling tar (1.35-r0)")
	if err != nil || !reflect.DeepEqual(after, before) {
		t.Fatal("same-version drift repair rejected", after, err)
	}
	world := "curl=8.16.0-r0\nlxcfs~6.0\ntar\n"
	if !alpineToolWorldPreserved(world, "tar\ncurl=8.16.0-r0\nlxcfs~6.0\ngzip\n", []string{"gzip"}, true) {
		t.Fatal("name-only addition rejected")
	}
	for _, current := range []string{world + "gzip=1.15-r0\n", world + "gzip\nzlib\n", "curl\nlxcfs~6.0\ntar\ngzip\n", "curl=8.16.0-r0\nlxcfs\ntar\ngzip\n"} {
		if alpineToolWorldPreserved(world, current, []string{"gzip"}, true) {
			t.Fatal("persistent dependency pins or modified admin constraints accepted", current)
		}
	}
	if !alpineToolWorldPreserved(world, world, nil, false) || alpineToolWorldPreserved(world, world+"gzip\n", nil, false) {
		t.Fatal("reinstall modified world constraints")
	}
}
