//go:build linux

package provisioning

import "testing"

func TestDebianToolInventoryAndCompletePinnedPlan(t *testing.T) {
	before, err := parseDebianToolInventory("apparmor:amd64\tinstalled\t4.0.1-1\nlibpopt0:amd64\tinstalled\t1.19-1\n")
	if err != nil {
		t.Fatal(err)
	}
	plan := "Inst apparmor [4.0.1-1] (4.0.1-1 Ubuntu:24.04/noble [amd64])\nInst rsync (3.2.7-1 Ubuntu:24.04/noble [amd64])"
	after, err := expectedDebianTools(before, plan)
	if err != nil || after["rsync:amd64"] != "3.2.7-1" || after["libpopt0:amd64"] != before["libpopt0:amd64"] {
		t.Fatal("complete installed baseline invalid", after, err)
	}
	for _, plan := range []string{"Inst apparmor [4.0.1-1] (4.0.2-1 Ubuntu:24.04/noble [amd64])", "Inst rsync (3.2.7-1 Ubuntu:24.04/noble)", "Inst apparmor [4.0.1-1] (4.0.1-1 Ubuntu:24.04/noble [amd64])\nInst apparmor [4.0.1-1] (4.0.1-1 Ubuntu:24.04/noble [amd64])", "Remv apparmor [4.0.1-1]", "Inst rsync unknown"} {
		if _, err := expectedDebianTools(before, plan); err == nil {
			t.Fatal("unreviewed/ambiguous pinned dependency accepted", plan)
		}
	}
	for _, output := range []string{"apparmor:amd64\tinstalled\t4.0.1\napparmor:amd64\tinstalled\t4.0.1", "invalid", "apparmor:amd64\tinstalled\tbad version"} {
		if _, err := parseDebianToolInventory(output); err == nil {
			t.Fatal("invalid package inventory accepted")
		}
	}
}
