//go:build linux

package provisioning

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestManagedDNSPatchInventoryBindsHostNamespaceAndReceipt(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned native receipt")
	}
	root, proc := t.TempDir(), t.TempDir()
	for _, pid := range []string{"1", "2"} {
		os.MkdirAll(filepath.Join(proc, pid, "ns"), 0700)
		os.Symlink("pid:[1]", filepath.Join(proc, pid, "ns/pid"))
		os.WriteFile(filepath.Join(proc, pid, "maps"), nil, 0600)
	}
	os.WriteFile(filepath.Join(proc, "2/comm"), []byte("dnsmasq\n"), 0600)
	os.Symlink("/usr/sbin/dnsmasq", filepath.Join(proc, "2/exe"))
	network := filepath.Join(root, "incusbr0")
	os.Mkdir(network, 0700)
	path := filepath.Join(network, "dnsmasq.pid")
	os.WriteFile(path, []byte("name: dnsmasq\nargs: [--conf-file=private]\npid: 2\n"), 0600)
	if old, err := managedDNSActivationPending(context.Background(), root, proc); err != nil || old {
		t.Fatal("current DNS falsely pending", old, err)
	}
	os.WriteFile(filepath.Join(proc, "2/maps"), []byte("a-b r-xp 0 0 0 /usr/sbin/dnsmasq (deleted)\n"), 0600)
	if old, err := managedDNSActivationPending(context.Background(), root, proc); err != nil || !old {
		t.Fatal("old running DNS executable ignored", old, err)
	}
	os.Remove(filepath.Join(proc, "2/ns/pid"))
	os.Symlink("pid:[2]", filepath.Join(proc, "2/ns/pid"))
	if _, err := managedDNSActivationPending(context.Background(), root, proc); err == nil {
		t.Fatal("guest PID namespace accepted")
	}
	for _, value := range []string{"pid: 2\npid: 3\n", "pid: 1\n", "pid: invalid\n"} {
		os.WriteFile(path, []byte(value), 0600)
		if _, err := managedDNSActivationPending(context.Background(), root, proc); err == nil {
			t.Fatal("ambiguous PID accepted")
		}
	}
	os.Remove(path)
	os.Mkdir(filepath.Join(network, "dnsmasq.hosts"), 0700)
	if old, err := managedDNSActivationPending(context.Background(), root, proc); err != nil || !old {
		t.Fatal("missing service receipt silently accepted for existing DHCP state", old, err)
	}
	os.Symlink("/etc/passwd", path)
	if _, err := managedDNSActivationPending(context.Background(), root, proc); err == nil {
		t.Fatal("symlink service receipt accepted")
	}
}

func TestNativeManagedDNSPatchActivation(t *testing.T) {
	if os.Getenv("INCUDAL_SYSINFO_COMPAT_TEST") != "disposable" || os.Getenv("INCUDAL_COMPAT_RELOAD_SCENARIO") != "empty-pool" {
		t.Skip("disposable already-verified empty Alpine host only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	data, err := os.ReadFile(compatJournalPath)
	var journal compatJournal
	if err != nil || json.Unmarshal(data, &journal) != nil || journal.Phase != "verified" {
		t.Fatal("verified original daemon journal unavailable", err)
	}
	p := &CompatPermit{RequestID: journal.RequestID, HostIdentity: journal.HostIdentity, ExpiresAt: time.Now().Add(240 * time.Second).Format(time.RFC3339Nano)}
	if err := authorizeEmptySecurityHost(ctx, p); err != nil {
		t.Fatal(err)
	}
	networkBefore, err := run(ctx, "incus", "query", "/1.0/networks/security-dns0")
	if err != nil {
		t.Fatal(err)
	}
	dnsPath, err := systemTool("dnsmasq")
	if err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(dnsPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(dnsPath+".security-test", data, 0755); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(dnsPath+".security-test", dnsPath); err != nil {
		t.Fatal(err)
	}
	oldDNS, err := managedDNSActivationPending(ctx, "/var/lib/incus/networks", "/proc")
	if err != nil || !oldDNS {
		t.Fatal("patched disk binary accepted as active DNS", oldDNS, err)
	}
	if err = repairEmptyHostServiceSecurity(ctx, p); err != nil {
		t.Fatal("original fenced Incus DNS activation", err)
	}
	networkAfter, err := run(ctx, "incus", "query", "/1.0/networks/security-dns0")
	if err != nil {
		t.Fatal(err)
	}
	var beforeNetwork, afterNetwork struct {
		Name   string
		Config map[string]string
	}
	if json.Unmarshal(networkBefore, &beforeNetwork) != nil || json.Unmarshal(networkAfter, &afterNetwork) != nil || !reflect.DeepEqual(beforeNetwork, afterNetwork) {
		t.Fatal("managed DNS activation changed original network configuration")
	}
	if strings.TrimSpace(beforeNetwork.Name) != "security-dns0" {
		t.Fatal("DNS fixture network identity changed")
	}
	t.Log("PASS managed DNS original binary replaced: exact empty-host fence, Incus-owned restart, current executable mappings and network configuration preserved")
}
