//go:build linux

package provisioning

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestStoppedAndHiddenGuestsCannotRequestEmptyHostMaintenance(t *testing.T) {
	if empty, err := confirmedEmptyHostInventory([]byte(`[]`)); err != nil || !empty {
		t.Fatal("confirmed empty inventory rejected", err)
	}
	for _, raw := range []string{`[{"name":"original","status":"Stopped"}]`, `[{"name":"original","status":"Running"}]`, `[{"name":"foreign","project":"another"}]`} {
		if empty, err := confirmedEmptyHostInventory([]byte(raw)); err != nil || empty {
			t.Fatal("occupied inventory became empty", raw, err)
		}
	}
	for _, raw := range []string{"", `null`, `{}`, `{"error":"unavailable"}`, `invalid`} {
		if empty, err := confirmedEmptyHostInventory([]byte(raw)); err == nil || empty {
			t.Fatal("unknown inventory became empty", raw)
		}
	}
}

func TestEmptyHostSecurityContinuesIndependentStages(t *testing.T) {
	first, third := errors.New("first failed"), errors.New("third failed")
	permit := &CompatPermit{}
	called := 0
	err := runEmptyHostSecurityStages(context.Background(), permit, func(ctx context.Context, p *CompatPermit) error {
		called++
		if p != permit {
			t.Fatal("authority changed")
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 60*time.Second {
			t.Fatal("stage deadline lost")
		}
		return first
	}, func(context.Context, *CompatPermit) error { called++; return nil }, func(context.Context, *CompatPermit) error { called++; return third })
	if called != 3 || !errors.Is(err, first) || !errors.Is(err, third) {
		t.Fatal("independent maintenance skipped or failure lost", called, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called = 0
	err = runEmptyHostSecurityStages(ctx, permit, func(context.Context, *CompatPermit) error { called++; return nil })
	if called != 0 || !errors.Is(err, context.Canceled) {
		t.Fatal("expired pass continued", called, err)
	}
}

func TestLxcfsSecurityRejectsOccupiedOrExpiredAuthority(t *testing.T) {
	p := &CompatPermit{RequestID: "11111111-1111-4111-8111-111111111111", HostIdentity: strings.Repeat("a", 64), ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339Nano), Guests: []CompatGuestPermit{{Name: "paid", UUID: "11111111-1111-4111-8111-111111111111", State: "Running"}}}
	if err := authorizeEmptySecurityHost(context.Background(), p); err == nil {
		t.Fatal("customer-bearing permit allowed a FUSE interruption")
	}
	p.Guests = nil
	p.ExpiresAt = time.Now().Add(-time.Minute).Format(time.RFC3339Nano)
	if err := authorizeEmptySecurityHost(context.Background(), p); err == nil {
		t.Fatal("expired empty-host authority accepted")
	}
	before := map[string]string{"lxcfs": "6.0.1-r0", "lxcfs-openrc": "6.0.1-r0", "fuse3-libs": "3.18.0-r0"}
	plan := "Upgrading lxcfs (6.0.1-r0 -> 6.0.1-r1)\nUpgrading lxcfs-openrc (6.0.1-r0 -> 6.0.1-r1)"
	if safeSecurityPackagePlan(plan, before) == nil {
		t.Fatal("live-host leaf updater was allowed to change LXCFS")
	}
	if err := safeSecurityPackagePlanFor(plan, before, securityLxcfsTargets); err != nil {
		t.Fatal("empty-host reviewed patch plan refused", err)
	}
}

func TestLxcfsOriginalDeletedExecutableReceipt(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root process evidence required")
	}
	root := t.TempDir()
	binary, pidPath := filepath.Join(root, "lxcfs"), filepath.Join(root, "lxcfs.pid")
	data, err := os.ReadFile("/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(binary, data, 0755); err != nil {
		t.Fatal(err)
	}
	process := exec.Command(binary, "30")
	process.Args[0] = "sleep"
	if err = process.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = process.Process.Kill(); _ = process.Wait() }()
	if err = os.WriteFile(pidPath, []byte(strconv.Itoa(process.Process.Pid)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = replacedLxcfsProcess(context.Background(), pidPath, binary); err == nil {
		t.Fatal("unchanged executable accepted as deleted original")
	}
	if err = os.WriteFile(binary+".new", data, 0755); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(binary+".new", binary); err != nil {
		t.Fatal(err)
	}
	if pid, err := replacedLxcfsProcess(context.Background(), pidPath, binary); err != nil || pid != process.Process.Pid {
		t.Fatal("same original process lost after package replaced its file", pid, err)
	}
	if _, err = replacedLxcfsProcess(context.Background(), pidPath, binary+".wrong"); err == nil {
		t.Fatal("other service accepted")
	}
	for _, value := range []string{fmt.Sprint(process.Process.Pid) + " extra", "1", "invalid"} {
		os.WriteFile(pidPath, []byte(value), 0600)
		if _, err = replacedLxcfsProcess(context.Background(), pidPath, binary); err == nil {
			t.Fatal("ambiguous process identity accepted")
		}
	}
	os.WriteFile(pidPath, []byte(strconv.Itoa(process.Process.Pid)), 0600)
	os.Chmod(pidPath, 0666)
	if _, err = replacedLxcfsProcess(context.Background(), pidPath, binary); err == nil {
		t.Fatal("writable PID identity accepted")
	}
}

func TestNativeLxcfsEmptyHostSecurityActivation(t *testing.T) {
	if os.Getenv("INCUDAL_SYSINFO_COMPAT_TEST") != "disposable" || os.Getenv("INCUDAL_COMPAT_RELOAD_SCENARIO") != "empty-pool" {
		t.Skip("disposable empty Alpine host only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	p := &CompatPermit{RequestID: "11111111-1111-4111-8111-111111111111", HostIdentity: strings.Repeat("a", 64), ExpiresAt: time.Now().Add(240 * time.Second).Format(time.RFC3339Nano)}
	for {
		if err := authorizeEmptySecurityHost(ctx, p); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("fixture startup operations did not settle")
		case <-time.After(time.Second):
		}
	}
	if err := repair(ctx); err != nil {
		// Fixed commands inside this disposable root only; no customer config
		// or credentials are printed when native package/tool startup fails.
		for _, tool := range required {
			flag := "--help"
			if tool == "unsquashfs" {
				flag = "-version"
			}
			output, probeErr := run(ctx, tool, flag)
			t.Logf("fixture tool %s exit=%v bytes=%d", tool, probeErr, len(output))
		}
		output, probeErr := run(ctx, "apk", "info", "-v", "lxcfs", "lxcfs-openrc", "apparmor-utils")
		t.Logf("fixture required package inventory: %s exit=%v", output, probeErr)
		t.Fatal(err)
	}
	t.Log("fixture host tools ready")
	if err := ensureResourceVisibility(ctx); err != nil {
		for _, action := range []string{"status", "start"} {
			output, probeErr := run(ctx, "rc-service", "lxcfs", action)
			t.Logf("fixture LXCFS %s: %s exit=%v", action, output, probeErr)
		}
		t.Fatal(err)
	}
	t.Log("fixture original LXCFS active")
	t.Run("pending-other-project-operation-before-instance", func(t *testing.T) {
		verifyNativeEmptyHostAllProjectOperations(t, ctx, p)
	})
	path := "/usr/bin/lxcfs"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path+".security-test", data, 0755); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(path+".security-test", path); err != nil {
		t.Fatal(err)
	}
	activate, done := context.WithTimeout(ctx, 60*time.Second)
	err = repairLxcfsSecurity(activate, p)
	done()
	if err != nil {
		t.Fatal("activate original empty-host FUSE service after executable replacement", err)
	}
	t.Log("fixture replaced original LXCFS activated within product deadline")
	receiptData, err := os.ReadFile(securityRuntimeReceiptPath)
	if err != nil {
		t.Fatal("runtime installation receipt unavailable", err)
	}
	receipt, err := readSecurityRuntimeReceipt(securityRuntimeReceiptPath)
	if err != nil || receipt == nil || receipt.Phase != "installed" {
		t.Fatal("signed runtime installation not durably confirmed", err)
	}
	loader, err := hashSecurityMuslLoader(ctx)
	if err != nil || loader != receipt.LoaderExpected {
		t.Fatal("actual loader differs from signature-verified candidate", err)
	}
	activate, done = context.WithTimeout(ctx, 60*time.Second)
	err = repairLxcfsSecurity(activate, p)
	done()
	if err != nil {
		t.Fatal("idempotent activation", err)
	}
	again, err := os.ReadFile(securityRuntimeReceiptPath)
	if err != nil || string(again) != string(receiptData) {
		t.Fatal("same-boot identical installation repeated its package transaction", err)
	}
	t.Log("PASS Alpine LXCFS/musl: exact empty-host authority, signed candidate loader, private installation receipt, original service activation and unchanged repeated receipt")
}

func verifyNativeEmptyHostAllProjectOperations(t *testing.T, ctx context.Context, permit *CompatPermit) {
	t.Helper()
	project := fmt.Sprintf("incudal-security-operation-%d", os.Getpid())
	if _, err := run(ctx, "incus", "project", "create", project, "-c", "features.profiles=false"); err != nil {
		t.Fatal("disposable nondefault project could not be created", err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var enteredOnce, releaseOnce sync.Once
	finish := func() { releaseOnce.Do(func() { close(release) }) }
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enteredOnce.Do(func() { close(entered) })
		<-release
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer func() {
		finish()
		cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		for {
			operations, err := run(cleanup, "incus", "query", "--raw", "/1.0/operations?recursion=1&all-projects=true")
			if err == nil && compatOperationsIdle(operations) {
				break
			}
			select {
			case <-cleanup.Done():
				t.Error("disposable other-project image operation did not finish")
				fixture.Close()
				return
			case <-time.After(100 * time.Millisecond):
			}
		}
		if _, err := run(cleanup, "incus", "project", "delete", project); err != nil {
			t.Error("disposable other-project operation cleanup failed", err)
		}
		fixture.Close()
	}()
	data, _ := json.Marshal(map[string]any{"public": false, "source": map[string]string{"type": "url", "mode": "pull", "url": fixture.URL + "/deliberately-pending-image"}})
	if _, err := run(ctx, "incus", "query", "--raw", "-X", "POST", "--data", string(data), "/1.0/images?project="+project); err != nil {
		t.Fatal("actual nondefault image download operation was not created", err)
	}
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("actual nondefault operation did not reach its bounded pending source")
	case <-time.After(10 * time.Second):
		t.Fatal("actual nondefault operation did not reach its pending source")
	}
	if err := verifyEmptySecurityHost(ctx, permit); err != nil {
		t.Fatal("image operation unexpectedly created an instance", err)
	}
	defaultOnly, err := run(ctx, "incus", "query", "--raw", "/1.0/operations?recursion=1")
	if err != nil || !compatOperationsIdle(defaultOnly) {
		t.Fatal("default-project fixture does not reproduce the missing-operation boundary", err)
	}
	allProjects, err := run(ctx, "incus", "query", "--raw", "/1.0/operations?recursion=1&all-projects=true")
	if err != nil || compatOperationsIdle(allProjects) {
		t.Fatal("actual pending other-project operation was not visible in all-projects", err)
	}
	before, err := os.ReadFile("/run/lxcfs.pid")
	if err != nil {
		t.Fatal("original FUSE process receipt unavailable", err)
	}
	if err := authorizeEmptySecurityHost(ctx, permit); err == nil {
		t.Fatal("all-projects image operation granted runtime maintenance authority")
	}
	if err := repairLxcfsSecurity(ctx, permit); err == nil {
		t.Fatal("runtime maintenance continued before an other-project operation finished")
	}
	after, err := os.ReadFile("/run/lxcfs.pid")
	if err != nil || string(after) != string(before) {
		t.Fatal("pending other-project operation interrupted the original FUSE service", err)
	}
	t.Log("PASS actual Incus nondefault operation: all-projects empty instance list, default task list idle, other project pending, runtime maintenance refused and original FUSE process retained")
}
