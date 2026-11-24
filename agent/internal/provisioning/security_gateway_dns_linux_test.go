//go:build linux

package provisioning

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestGatewayDNSOnlyReviewedHistoricalSources(t *testing.T) {
	for _, hash := range []string{gatewayDNSSecurityHelperHash, gatewayDNSLegacyHelperHash} {
		if !reviewedGatewayDNSHelper(hash) {
			t.Fatal("original reviewed source refused")
		}
	}
	for _, hash := range []string{"", gatewayDNSLegacyHelperHash[:63], "f" + gatewayDNSLegacyHelperHash[1:]} {
		if reviewedGatewayDNSHelper(hash) {
			t.Fatal("unknown or tampered helper accepted")
		}
	}
}

func TestNativeGatewayDNSPythonSecurityActivation(t *testing.T) {
	if os.Getenv("INCUDAL_SYSINFO_COMPAT_TEST") != "disposable" || os.Getenv("INCUDAL_COMPAT_RELOAD_SCENARIO") != "empty-pool" {
		t.Skip("disposable original OpenRC gateway DNS service only")
	}
	helperPath := "/out/gateway-dns-helper"
	expectedHelperHash := gatewayDNSSecurityHelperHash
	if os.Getenv("INCUDAL_GATEWAY_DNS_LEGACY_TEST") == "1" {
		helperPath = "/out/gateway-dns-legacy-helper"
		expectedHelperHash = gatewayDNSLegacyHelperHash
	}
	helper, err := os.ReadFile(helperPath)
	if err != nil {
		t.Fatal(err)
	}
	helperHash := sha256.Sum256(helper)
	if hex.EncodeToString(helperHash[:]) != expectedHelperHash {
		t.Fatal("native fixture is not the exact selected historical source")
	}
	for _, dir := range []string{"/usr/local/libexec", "/etc/wireguard"} {
		if err = os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	// A literal endpoint never invokes wg set in this fixture. The original
	// daemon and supervisor are real; all private identity files stay unchanged.
	config := "[Interface]\nAddress = 10.253.240.2/32\nPrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n[Peer]\nPublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nAllowedIPs = 10.253.240.1/32\nEndpoint = 8.8.4.4:51820\nPersistentKeepalive = 25\n"
	for path, data := range map[string]string{"/usr/local/libexec/incudal-gateway-dns": string(helper), "/etc/init.d/incudal-gateway-dns": gatewayDNSSecurityUnit, "/etc/wireguard/incudal-mgmt.conf": config, "/etc/incudal-onboarding-id": "11111111-1111-4111-8111-111111111111\n", "/etc/incudal-gateway-dns.json": "{}\n"} {
		mode := os.FileMode(0600)
		if path == "/usr/local/libexec/incudal-gateway-dns" || path == "/etc/init.d/incudal-gateway-dns" {
			mode = 0755
		}
		if err = os.WriteFile(path, []byte(data), mode); err != nil {
			t.Fatal(err)
		}
	}
	// Need net is a deployment dependency; this disposable loopback network is
	// already configured by the enclosing original runtime fixture.
	cmd := exec.Command("/sbin/rc-service", "incudal-gateway-dns", "start")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err = cmd.Run(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		// This PID namespace has no OpenRC init to reap stopped supervisors.
		// Bound fixture teardown; namespace exit cleans its remaining children.
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(cleanup, "/sbin/rc-service", "incudal-gateway-dns", "stop")
		cmd.WaitDelay = time.Second
		_ = cmd.Run()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	before, err := managedGatewayDNSProcess(ctx)
	if err != nil || before.pending {
		t.Fatal("original supervised Python identity unavailable", err)
	}
	python, err := filepath.EvalSymlinks("/usr/bin/python3")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(python)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(python+".security-test", data, 0755); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(python+".security-test", python); err != nil {
		t.Fatal(err)
	}
	if err = repairGatewayDNSPythonSecurity(ctx); err != nil {
		t.Fatal(err)
	}
	after, err := managedGatewayDNSProcess(ctx)
	if err != nil || after.pending || after.pid == before.pid || after.supervisor != before.supervisor || !reflect.DeepEqual(after.files, before.files) {
		t.Fatal("original supervisor did not load installed interpreter", err)
	}
	if err = repairGatewayDNSPythonSecurity(ctx); err != nil {
		t.Fatal("idempotent current service", err)
	}
	if err = os.WriteFile("/usr/local/libexec/incudal-gateway-dns", append(append([]byte{}, helper...), []byte("# custom\n")...), 0755); err != nil {
		t.Fatal(err)
	}
	if err = repairGatewayDNSPythonSecurity(ctx); err == nil {
		t.Fatal("unknown helper source accepted")
	}
	if err = os.WriteFile("/usr/local/libexec/incudal-gateway-dns", helper, 0755); err != nil {
		t.Fatal(err)
	}
	unchanged, err := managedGatewayDNSProcess(ctx)
	if err != nil || unchanged.pid != after.pid {
		t.Fatal("refused helper touched running child", err)
	}
	unit, err := os.ReadFile("/etc/init.d/incudal-gateway-dns")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile("/etc/init.d/incudal-gateway-dns", append(unit, []byte("# custom\n")...), 0755); err != nil {
		t.Fatal(err)
	}
	if err = repairGatewayDNSPythonSecurity(ctx); err == nil {
		t.Fatal("changed administrator service accepted")
	}
	if err = os.WriteFile("/etc/init.d/incudal-gateway-dns", unit, 0755); err != nil {
		t.Fatal(err)
	}
	final, err := managedGatewayDNSProcess(ctx)
	if err != nil || final.pid != after.pid {
		t.Fatal("refused custom service touched running child", err)
	}
	t.Log("PASS actual OpenRC supervised DNS: exact source", expectedHelperHash, "same supervisor, installed Python, original identity/network configuration, idempotency, unknown-helper and custom-unit rejection")
}
