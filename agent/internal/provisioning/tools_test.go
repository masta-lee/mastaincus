package provisioning

import (
	"reflect"
	"testing"
)

func TestToolDriftSelectsOnlyBrokenOwnerPackages(t *testing.T) {
	if !reflect.DeepEqual(brokenToolPackages([]string{"aa-exec"}, true), []string{"apparmor-utils"}) || !reflect.DeepEqual(brokenToolPackages([]string{"aa-exec"}, false), []string{"apparmor"}) {
		t.Fatal("one AppArmor tool drift reinstalled unrelated LXCFS/storage services")
	}
	if !reflect.DeepEqual(brokenToolPackages([]string{"btrfs", "btrfstune", "mkfs.btrfs"}, false), []string{"btrfs-progs"}) {
		t.Fatal("duplicate owners in repair transaction")
	}
}

func TestDistributionPackages(t *testing.T) {
	for _, release := range []string{"ID=alpine\nVERSION_ID=3.22.2", "ID=\"alpine\"\nVERSION_ID=3.24.3", "ID=debian", "ID=ubuntu"} {
		p, err := packagesFor(release)
		if err != nil || len(p) < 7 {
			t.Fatalf("missing tools: %v", err)
		}
		if p[0] != "apparmor" && p[0] != "apparmor-utils" {
			t.Fatal(p)
		}
	}
	if _, err := packagesFor("ID=unknown"); err == nil {
		t.Fatal("unsupported distribution accepted")
	}
}
