//go:build linux

package provisioning

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestLegacyWorldPlanOnlyConfirmedHistoricalConstraints(t *testing.T) {
	packages := map[string]string{"lxcfs": "6.0.1-r1", "lvm2": "2.03.35-r2", "curl": "8.23.0-r0", "libapparmor": "4.1.7-r1"}
	before := "# preserve bytes\nlxcfs=6.0.1-r1\nlvm2=2.03.35-r2\ncurl=8.23.0-r0\nlibapparmor@custom=4.1.7-r1\n"
	beforePackages := map[string]string{}
	for name, version := range packages {
		beforePackages[name] = version
	}
	after, err := legacyWorldPlan(before, packages)
	if err != nil || after != "# preserve bytes\nlxcfs\nlvm2\ncurl=8.23.0-r0\nlibapparmor@custom=4.1.7-r1\n" || !reflect.DeepEqual(beforePackages, packages) {
		t.Fatal("historical-only immutable migration", after, err)
	}
	for _, atom := range []string{"lxcfs=6.0.2-r0", "lxcfs~6.0", "lxcfs<7", "lxcfs@testing=6.0.1-r1", "curl=8.23.0-r0"} {
		if next, err := legacyWorldPlan(atom, packages); err != nil || next != atom {
			t.Fatal("administrator constraint changed", atom, next, err)
		}
	}
	for _, packages := range []map[string]string{{"lxcfs": "6.0.2-r0"}, {"curl": "8.23.0-r0"}} {
		if next, err := legacyWorldPlan("lxcfs=6.0.1-r1", packages); err != nil || next != "lxcfs=6.0.1-r1" {
			t.Fatal("absent/different installed version adopted", next, err)
		}
	}
	for _, text := range []string{"lxcfs\nlxcfs=6.0.1-r1\n", "lxcfs=6.0.1-r1\x00", "lxcfs\r\n", "unknown=", "lxcfs=", "lxcfs=6.0.1-r1 trailing", strings.Repeat("a", 65537)} {
		if _, err := legacyWorldPlan(text, packages); err == nil {
			t.Fatal("malformed or conflicting constraints accepted")
		}
	}
	full := map[string]string{}
	lines := []string{}
	for name, version := range legacyAlpineWorldVersions {
		full[name] = version
		lines = append(lines, name+"="+version)
	}
	next, err := legacyWorldPlan(strings.Join(lines, "\n"), full)
	if err != nil || strings.Contains(next, "=") || len(strings.Split(next, "\n")) != len(full) {
		t.Fatal("complete historical AppArmor/LVM/LXCFS dependency catalog not migrated", err)
	}
}

func legacyWorldFixture(t *testing.T) (string, string, string, map[string]string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("actual root-owned file and directory publication")
	}
	directory, err := os.MkdirTemp("/root", "legacy-world-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	world, receipt := filepath.Join(directory, "world"), filepath.Join(directory, "receipt.json")
	if err = os.WriteFile(world, []byte("# original\nlxcfs=6.0.1-r1\nlvm2=2.03.35-r2\ncurl=8.23.0-r0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	return world, receipt, "11111111-1111-4111-8111-111111111111", map[string]string{"lxcfs": "6.0.1-r1", "lvm2": "2.03.35-r2", "curl": "8.23.0-r0"}
}

func TestLegacyWorldPublicationAndLaterAdministratorPin(t *testing.T) {
	world, receiptPath, node, packages := legacyWorldFixture(t)
	before, _ := os.ReadFile(world)
	readInventory := func() (map[string]string, error) { return packages, nil }
	if err := migrateLegacyWorldFiles(context.Background(), world, receiptPath, node, "3.24", readInventory); err != nil {
		t.Fatal(err)
	}
	var receipt legacyWorldReceipt
	data, _ := os.ReadFile(receiptPath)
	if json.Unmarshal(data, &receipt) != nil || receipt.Phase != "completed" || receipt.Before != string(before) || receipt.BeforeHash != legacyWorldHash(string(before)) {
		t.Fatal("original evidence not preserved")
	}
	info, _ := os.Stat(receiptPath)
	if info.Mode().Perm() != 0600 {
		t.Fatal("receipt must remain private")
	}
	if err := os.WriteFile(world, before, 0644); err != nil {
		t.Fatal(err)
	}
	if err := migrateLegacyWorldFiles(context.Background(), world, receiptPath, node, "3.24", func() (map[string]string, error) { t.Fatal("completed migration repeated inventory"); return nil, nil }); err != nil {
		t.Fatal(err)
	}
	current, _ := os.ReadFile(world)
	if string(current) != string(before) {
		t.Fatal("later administrator's identical pin removed")
	}
}

func TestLegacyWorldPreparedResumeAndChangedWriter(t *testing.T) {
	for _, phase := range []string{"before", "after", "changed", "inventory"} {
		t.Run(phase, func(t *testing.T) {
			world, receiptPath, node, packages := legacyWorldFixture(t)
			before, _ := os.ReadFile(world)
			after, _ := legacyWorldPlan(string(before), packages)
			receipt := legacyWorldReceipt{Version: 1, Recipe: legacyWorldRecipe, Node: node, Architecture: runtime.GOARCH, Branch: "3.24", Phase: "prepared", Before: string(before), After: after, BeforeHash: legacyWorldHash(string(before)), AfterHash: legacyWorldHash(after), Mode: 0644, Packages: packages}
			data, _ := json.Marshal(receipt)
			if err := os.WriteFile(receiptPath, data, 0600); err != nil {
				t.Fatal(err)
			}
			want := after
			if phase == "after" {
				_ = os.WriteFile(world, []byte(after), 0644)
			} else if phase == "changed" {
				want = string(before) + "new-admin~1\n"
				_ = os.WriteFile(world, []byte(want), 0644)
			}
			err := migrateLegacyWorldFiles(context.Background(), world, receiptPath, node, "3.24", func() (map[string]string, error) {
				if phase == "inventory" {
					return map[string]string{"lxcfs": "6.0.2-r0"}, nil
				}
				return packages, nil
			})
			if phase == "inventory" {
				if err == nil {
					t.Fatal("changed package state accepted")
				}
				want = string(before)
			} else if err != nil {
				t.Fatal(err)
			}
			current, _ := os.ReadFile(world)
			if string(current) != want {
				t.Fatal("wrong publication/administrator overwrite", string(current))
			}
		})
	}
}

func TestLegacyWorldFilesRejectUnsafeAndCancelled(t *testing.T) {
	world, receipt, node, packages := legacyWorldFixture(t)
	if err := os.Chmod(world, 0666); err != nil {
		t.Fatal(err)
	}
	if err := migrateLegacyWorldFiles(context.Background(), world, receipt, node, "3.24", func() (map[string]string, error) { return packages, nil }); err == nil {
		t.Fatal("writable world accepted")
	}
	_ = os.Chmod(world, 0644)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := migrateLegacyWorldFiles(ctx, world, receipt, node, "3.24", nil); err == nil {
		t.Fatal("cancelled migration accepted")
	}
	if _, err := os.Stat(receipt); !os.IsNotExist(err) {
		t.Fatal("cancelled migration created receipt")
	}
	_ = os.Symlink(world, receipt)
	if err := migrateLegacyWorldFiles(context.Background(), world, receipt, node, "3.24", func() (map[string]string, error) { return packages, nil }); err == nil {
		t.Fatal("linked receipt accepted")
	}
}

func TestNativeLegacyWorldUsesAPKLockAndPreservesInstalledPackages(t *testing.T) {
	if os.Getenv("INCUDAL_LEGACY_WORLD_NATIVE_TEST") != "disposable" {
		t.Skip("disposable enrolled Alpine root only")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required")
	}
	nodePath := "/etc/incudal-onboarding-id"
	if _, err := os.Stat(nodePath); !os.IsNotExist(err) {
		t.Fatal("fixture must have no real enrollment")
	}
	world, err := os.ReadFile("/etc/apk/world")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.WriteFile("/etc/apk/world", world, 0644)
		_ = os.Remove(nodePath)
		_ = os.Remove("/var/lib/incudal-agent/legacy-apk-world-v1.json")
	})
	if err := os.WriteFile(nodePath, []byte("11111111-1111-4111-8111-111111111111\n"), 0600); err != nil {
		t.Fatal(err)
	}
	permit := &LegacyWorldPermit{Node: "11111111-1111-4111-8111-111111111111", Recipe: legacyWorldRecipe, ExpiresAt: time.Now().Add(2 * time.Minute).Format(time.RFC3339Nano)}
	maintenancePath := "/var/lib/incudal-hardening/maintenance.json"
	maintenance, maintenanceErr := os.ReadFile(maintenancePath)
	if maintenanceErr == nil {
		var state struct {
			Phase string `json:"phase"`
		}
		if json.Unmarshal(maintenance, &state) != nil || state.Phase != "preparing" {
			t.Fatal("fixture must not contain completed real maintenance")
		}
		t.Cleanup(func() { _ = os.WriteFile(maintenancePath, maintenance, 0600) })
		if err := migrateLegacyAlpineWorld(context.Background(), permit); err == nil {
			t.Fatal("active previous package maintenance accepted")
		}
		_ = os.Remove(maintenancePath)
	} else if !os.IsNotExist(maintenanceErr) {
		t.Fatal(maintenanceErr)
	}
	before, err := run(context.Background(), "apk", "info", "-v")
	if err != nil {
		t.Fatal(err)
	}
	installed, err := securityInstalledPackages(string(before))
	if err != nil {
		t.Fatal(err)
	}
	fixtureWorld := string(world)
	if fixtureWorld != "" && !strings.HasSuffix(fixtureWorld, "\n") {
		fixtureWorld += "\n"
	}
	rootPackages := map[string]bool{}
	for _, atom := range strings.Split(strings.TrimSpace(fixtureWorld), "\n") {
		if atom != "" && !strings.HasPrefix(atom, "#") {
			name := strings.FieldsFunc(atom, func(r rune) bool { return strings.ContainsRune("@=~<>", r) })
			if len(name) > 0 {
				rootPackages[name[0]] = true
			}
		}
	}
	for _, name := range []string{"libapparmor", "apparmor"} {
		if installed[name] == legacyAlpineWorldVersions[name] && (!rootPackages[name] || strings.Contains("\n"+fixtureWorld, "\n"+name+"\n")) {
			fixtureWorld = strings.ReplaceAll(fixtureWorld, name+"\n", "") + name + "=" + installed[name] + "\n"
		}
	}
	if err := os.WriteFile("/etc/apk/world", []byte(fixtureWorld), 0644); err != nil {
		t.Fatal(err)
	}
	want, err := legacyWorldPlan(fixtureWorld, installed)
	if err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.Open("/lib/apk/db/lock", syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		syscall.Close(fd)
		t.Fatal(err)
	}
	if err := migrateLegacyAlpineWorld(context.Background(), permit); err == nil {
		t.Fatal("active apk database writer not excluded")
	}
	_ = syscall.Flock(fd, syscall.LOCK_UN)
	_ = syscall.Close(fd)
	if err := migrateLegacyAlpineWorld(context.Background(), permit); err != nil {
		t.Fatal(err)
	}
	after, err := run(context.Background(), "apk", "info", "-v")
	if err != nil || string(before) != string(after) {
		t.Fatal("world migration changed installed packages", err)
	}
	current, _ := os.ReadFile("/etc/apk/world")
	if string(current) != want {
		t.Fatal("historical installed pin not migrated or absent package constraint changed")
	}
	t.Log("actual migration kept the complete installed inventory and required packages; inherited apk lock excludes concurrent writers")
}

func TestLegacyWorldPermitRejectsMissingExpiredAndUnknownNode(t *testing.T) {
	p := &LegacyWorldPermit{Node: "11111111-1111-4111-8111-111111111111", Recipe: legacyWorldRecipe, ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339Nano)}
	if !validLegacyWorldPermit(p) {
		t.Fatal("current enrollment permit rejected")
	}
	for _, bad := range []*LegacyWorldPermit{nil, {}, {Node: p.Node, Recipe: p.Recipe, ExpiresAt: time.Now().Add(-time.Second).Format(time.RFC3339Nano)}, {Node: p.Node, Recipe: p.Recipe, ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339Nano)}, {Node: "another", Recipe: p.Recipe, ExpiresAt: p.ExpiresAt}, {Node: p.Node, Recipe: "unknown", ExpiresAt: p.ExpiresAt}} {
		if validLegacyWorldPermit(bad) {
			t.Fatal("invalid adoption authority accepted")
		}
	}
}
