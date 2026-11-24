//go:build linux

package provisioning

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCompatibilityStartingDaemonRequiresCurrentExecutable(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned service receipt; native CI")
	}
	ctx := context.Background()
	pidPath := filepath.Join(t.TempDir(), "incusd.pid")
	binary, err := os.Readlink("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	hash, err := hashCompatReader(ctx, f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if pid, err := compatStartingDaemon(ctx, pidPath, binary, hash); err != nil || pid != 0 {
		t.Fatal("absent PID", pid, err)
	}
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		t.Fatal(err)
	}
	if pid, err := compatStartingDaemon(ctx, pidPath, binary, hash); err != nil || pid != os.Getpid() {
		t.Fatal("current process lost", pid, err)
	}
	if _, err := compatStartingDaemon(ctx, pidPath, binary, strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong content accepted")
	}
	if _, err := compatStartingDaemon(ctx, pidPath, "/unexpected", hash); err == nil {
		t.Fatal("reused PID accepted as daemon")
	}
	if err := os.Chmod(pidPath, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := compatStartingDaemon(ctx, pidPath, binary, hash); err == nil {
		t.Fatal("unsafe service receipt accepted")
	}
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := waitCompatReady(ctx, hash); err == nil {
		t.Fatal("cancelled readiness accepted")
	}
}
func TestCompatibilityRejectsPublishedBinaryWithOldRunningInode(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned process evidence")
	}
	directory := t.TempDir()
	binary, pidPath := filepath.Join(directory, "incusd"), filepath.Join(directory, "incusd.pid")
	old, err := os.ReadFile("/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(binary, old, 0755); err != nil {
		t.Fatal(err)
	}
	process := exec.Command(binary, "30")
	// Alpine's /bin/sleep is a BusyBox applet selected by argv[0]. Retain
	// that identity after copying it to the disposable Incus-named fixture.
	process.Args[0] = "sleep"
	if err = process.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = process.Process.Kill(); _ = process.Wait() }()
	if err = os.WriteFile(pidPath, []byte(strconv.Itoa(process.Process.Pid)), 0600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if pid, err := compatStartingDaemon(ctx, pidPath, binary, compatHash(old)); err != nil || pid != process.Process.Pid {
		t.Fatal("original running inode not confirmed", pid, err)
	}
	newBytes, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	if compatHash(newBytes) == compatHash(old) {
		newBytes = append(newBytes, []byte("changed fixture bytes")...)
	}
	staged := filepath.Join(directory, "staged")
	if err = os.WriteFile(staged, newBytes, 0755); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(staged, binary); err != nil {
		t.Fatal(err)
	}
	if _, err = compatStartingDaemon(ctx, pidPath, binary, compatHash(newBytes)); err == nil {
		t.Fatal("installed new bytes must not attest to the old running executable")
	}
}

func TestCompatibilityRetiresOnlyExitedPIDReceipt(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned service receipt; native CI")
	}
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "incusd.pid")
	if err := retireExitedCompatPID(ctx, path, strings.Repeat("0", 64)); err != nil {
		t.Fatal("absent receipt", err)
	}
	if err := os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		t.Fatal(err)
	}
	if err := retireExitedCompatPID(ctx, path, strings.Repeat("0", 64)); err == nil {
		t.Fatal("live reused PID receipt removed")
	}
	command := exec.Command("/bin/true")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer command.Wait()
	deadline := time.Now().Add(5 * time.Second)
	for {
		stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", command.Process.Pid))
		if err != nil {
			t.Fatal(err)
		}
		at := strings.LastIndex(string(stat), ") ")
		if at >= 0 && strings.HasPrefix(string(stat)[at+2:], "Z ") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fixture child did not become zombie")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := os.WriteFile(path, []byte(strconv.Itoa(command.Process.Pid)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := retireExitedCompatPID(ctx, path, strings.Repeat("0", 64)); err != nil {
		t.Fatal("unchanged zombie receipt blocked service restart", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("zombie receipt retained", err)
	}
	if err := os.WriteFile(path, []byte(strconv.Itoa(command.Process.Pid)), 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if err := retireExitedCompatPID(ctx, path, strings.Repeat("0", 64)); err == nil {
		t.Fatal("unsafe exited receipt removed")
	}
}

func TestCompatPermitAndGuestIdentity(t *testing.T) {
	for _, versions := range [][2]string{{"7.0.1", "7.6.0"}, {"", ""}, {"7.6.0", "7.0.1"}} {
		if compatRollbackSafe(compatJournal{OldVersion: versions[0], NewVersion: versions[1]}) {
			t.Fatal("unsafe schema downgrade accepted", versions)
		}
	}
	if !compatRollbackSafe(compatJournal{OldVersion: "7.6.0", NewVersion: "7.6.0"}) {
		t.Fatal("same-version rollback refused")
	}
	if !compatSourceVersion("7.6") || !compatRollbackSafe(compatJournal{OldVersion: "7.6", NewVersion: "7.6.0"}) || compatSourceVersion("7.6.1") {
		t.Fatal("exact upstream version alias must retain same-version rollback without accepting unknown patches")
	}
	good := &CompatPermit{RequestID: "11111111-1111-4111-8111-111111111111", HostIdentity: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ExpiresAt: time.Now().Add(60 * time.Second).UTC().Format(time.RFC3339Nano)}
	if !validCompatPermit(good) || validCompatPermit(nil) {
		t.Fatal("permit validation")
	}
	for _, v := range []CompatPermit{{}, {RequestID: good.RequestID, HostIdentity: good.HostIdentity, ExpiresAt: time.Now().Add(-time.Second).Format(time.RFC3339Nano)}} {
		if validCompatPermit(&v) {
			t.Fatal("expired/missing permit accepted")
		}
	}
	a := []compatGuest{{Name: "one", Status: "Running", Config: map[string]string{"volatile.uuid": "original"}}}
	if !sameCompatGuests(a, a) || sameCompatGuests(a, []compatGuest{{Name: "one", Status: "Running", Config: map[string]string{"volatile.uuid": "other"}}}) {
		t.Fatal("guest identity must be preserved")
	}
	if !compatibleCurrentGuests(a, []compatGuest{{Name: "one", Status: "Stopped", Config: map[string]string{"volatile.uuid": "original"}}}) || compatibleCurrentGuests([]compatGuest{{Name: "one", Status: "Stopped", Config: map[string]string{"volatile.uuid": "original"}}}, a) {
		t.Fatal("new expiry stop respected without resurrecting guest")
	}
	if _, e := compatProcessStart(os.Getpid()); e != nil {
		t.Fatal(e)
	}
}
func TestEmbeddedCompatibilityPayload(t *testing.T) {
	if os.Getenv("INCUDAL_COMPAT_PAYLOAD_TEST") != "1" {
		t.Skip("release payload only")
	}
	b, e := compatibilityBinary()
	if e != nil || len(b) < 1000000 {
		t.Fatal("payload", e)
	}
}
func TestCompatibilityEmptyAndActiveOperations(t *testing.T) {
	for _, response := range []string{`{"type":"sync","status_code":200,"metadata":{}}`, `{"type":"sync","status_code":200,"metadata":{"success":[{"status":"Success"}]}}`} {
		if !compatOperationsIdle([]byte(response)) {
			t.Fatal("idle response rejected")
		}
	}
	for _, response := range []string{"", `{}`, `{"type":"error","status_code":500,"metadata":{}}`, `{"type":"sync","status_code":200,"metadata":null}`, `{"type":"sync","status_code":200,"metadata":{"running":[{"status":"Running"}]}}`, `{"type":"sync","status_code":200,"metadata":{"unknown":[{}]}}`} {
		if compatOperationsIdle([]byte(response)) {
			t.Fatal("unconfirmed response accepted")
		}
	}
}
func TestNativeCompatibilityAutomaticReload(t *testing.T) {
	if os.Getenv("INCUDAL_SYSINFO_COMPAT_TEST") != "disposable" {
		t.Skip("disposable Alpine root only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	before, e := compatGuests(ctx)
	if e != nil || len(before) != 1 || before[0].Name != "native-sysinfo" {
		t.Fatal("disposable guest scope", e)
	}
	if empty, err := localHostMaintenanceEmpty(ctx); err != nil || empty {
		t.Fatal("actual occupied all-project inventory cannot request empty-host maintenance", err)
	}
	// The fixture launched a real original daemon rather than OpenRC. Record
	// that actual PID as an installed service would, without replacing the guest.
	raw, e := os.ReadFile("/run/incus/incusd.pid")
	if e != nil {
		t.Fatal(e)
	}
	part := strings.TrimSpace(string(raw))
	pid, e := strconv.Atoi(part)
	exe, _ := os.Readlink("/proc/" + part + "/exe")
	cgroup, _ := os.ReadFile("/proc/" + part + "/cgroup")
	var state struct {
		PID int `json:"pid"`
	}
	data, readErr := run(ctx, "incus", "query", "/1.0/instances/native-sysinfo/state")
	if e != nil || pid < 2 || exe != "/usr/sbin/incusd" || readErr != nil || json.Unmarshal(data, &state) != nil || pid == state.PID || strings.Contains(string(cgroup), "lxc.monitor.") {
		t.Fatal("original daemon pid")
	}
	if e = os.MkdirAll("/var/lib/incudal-agent", 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile("/run/incus/incusd.pid", []byte(strconv.Itoa(pid)), 0600); e != nil {
		t.Fatal(e)
	}
	p := &CompatPermit{RequestID: "11111111-1111-4111-8111-111111111111", HostIdentity: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ExpiresAt: time.Now().Add(240 * time.Second).UTC().Format(time.RFC3339Nano)}
	for _, g := range before {
		p.Guests = append(p.Guests, CompatGuestPermit{Name: g.Name, UUID: g.Config["volatile.uuid"], State: g.Status})
	}
	if os.Getenv("INCUDAL_COMPAT_RELOAD_SCENARIO") == "previous-generation" {
		original, readErr := os.ReadFile("/usr/sbin/incusd")
		start, startErr := compatProcessStart(pid)
		if readErr != nil || startErr != nil {
			t.Fatal("previous generation fixture", readErr, startErr)
		}
		if e = os.WriteFile(compatBackupPath, original, 0700); e != nil {
			t.Fatal(e)
		}
		j := compatJournal{Version: 1, OldHash: compatHash(original), NewHash: compatHash(original), PID: pid, ProcessStart: start, RequestID: p.RequestID, HostIdentity: p.HostIdentity, Phase: "verified", Guests: before}
		if e = saveCompatJournal(j); e != nil {
			t.Fatal(e)
		}
	}
	if os.Getenv("INCUDAL_COMPAT_RELOAD_SCENARIO") == "prepared-resume" {
		original, readErr := os.ReadFile("/usr/sbin/incusd")
		fixed, payloadErr := compatibilityBinary()
		start, startErr := compatProcessStart(pid)
		if readErr != nil || payloadErr != nil || startErr != nil {
			t.Fatal("prepared fixture", readErr, payloadErr, startErr)
		}
		if e = os.WriteFile(compatBackupPath, original, 0700); e != nil {
			t.Fatal(e)
		}
		j := compatJournal{Version: 1, OldHash: compatHash(original), NewHash: compatHash(fixed), PID: pid, ProcessStart: start, RequestID: p.RequestID, HostIdentity: p.HostIdentity, Phase: "prepared", Guests: before}
		if e = saveCompatJournal(j); e != nil {
			t.Fatal(e)
		}
		if e = replaceCompatBinary(fixed); e != nil {
			t.Fatal(e)
		}
		if e = prepareIncusCompatibility(ctx, p); e != nil {
			t.Fatal("prepared recovery", e)
		}
		current, _ := os.ReadFile("/usr/sbin/incusd")
		if compatHash(current) != j.OldHash {
			t.Fatal("prepared recovery did not restore original binary")
		}
	}
	if os.Getenv("INCUDAL_COMPAT_RELOAD_SCENARIO") == "rollback-retry" {
		// Fail the actual OpenRC start_pre hook once. An already-started network
		// dependency can ignore a missing interfaces file and is not a reliable
		// failure injection. Restore the exact original script before retry.
		path := "/etc/init.d/incusd"
		original, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if e = os.WriteFile(path, append(append([]byte{}, original...), []byte("\nstart_pre() { return 1; }\n")...), 0755); e != nil {
			t.Fatal(e)
		}
		e = prepareIncusCompatibility(ctx, p)
		if restoreErr := os.WriteFile(path, original, 0755); restoreErr != nil {
			t.Fatal(restoreErr)
		}
		if e == nil {
			t.Fatal("failed service startup reported success")
		}
		t.Log("injected startup result", e)
		journalData, readErr := os.ReadFile(compatJournalPath)
		var j compatJournal
		if readErr != nil || json.Unmarshal(journalData, &j) != nil || j.Phase != "rolling-back" && j.Phase != "reloading" {
			t.Fatal("failed service lost durable reload intent", readErr)
		}
		if compatRollbackSafe(j) {
			if e = prepareIncusCompatibility(ctx, p); e == nil || !strings.Contains(e.Error(), "rolled back; retry pending") {
				t.Fatal("automatic rollback", e)
			}
			current, _ := os.ReadFile("/usr/sbin/incusd")
			if compatHash(current) != j.OldHash {
				t.Fatal("rollback binary not restored")
			}
		} else {
			current, _ := os.ReadFile("/usr/sbin/incusd")
			if compatHash(current) != j.NewHash {
				t.Fatal("cross-version retry lost verified candidate")
			}
			if e = prepareIncusCompatibility(ctx, p); e != nil {
				t.Fatal("schema-safe forward retry", e)
			}
		}
		restored, readErr := compatGuests(ctx)
		if readErr != nil || !sameCompatGuests(before, restored) {
			t.Fatal("rollback changed guest", readErr)
		}
	}
	for {
		e = prepareIncusCompatibility(ctx, p)
		if e == nil || !strings.Contains(e.Error(), "waits for active operations") {
			break
		}
		// A recovered original daemon can still be settling its real Incus
		// operations. Exercise the same bounded retry as the Agent; do not
		// cancel operations or waive the product's idle requirement.
		select {
		case <-ctx.Done():
			diagnosticCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
			operations, _ := run(diagnosticCtx, "incus", "query", "/1.0/operations?recursion=1&all-projects=true")
			stop()
			t.Log("disposable operations", string(operations))
			t.Fatal("automatic reload did not become idle", ctx.Err())
		case <-time.After(time.Second):
		}
	}
	if e != nil {
		t.Fatal("automatic reload", e)
	}
	after, e := compatGuests(ctx)
	if e != nil || !sameCompatGuests(before, after) {
		t.Fatal("guest changed", e)
	}
	if e = prepareIncusCompatibility(ctx, p); e != nil {
		t.Fatal("idempotency", e)
	}
	if os.Getenv("INCUDAL_COMPAT_RELOAD_SCENARIO") == "previous-generation" {
		previous, readErr := os.ReadFile(compatBackupPath)
		if readErr != nil {
			t.Fatal(readErr)
		}
		archived, readErr := os.ReadFile(compatBackupPath + "." + compatHash(previous))
		if readErr != nil || compatHash(archived) != compatHash(previous) {
			t.Fatal("previous rollback archive not preserved", readErr)
		}
	}
}
func TestNativeCompatibilityEmptyPoolReload(t *testing.T) {
	if os.Getenv("INCUDAL_SYSINFO_COMPAT_TEST") != "disposable" || os.Getenv("INCUDAL_COMPAT_RELOAD_SCENARIO") != "empty-pool" {
		t.Skip("disposable empty pool only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	rows, err := compatGuests(ctx)
	if err != nil || len(rows) != 0 {
		t.Fatal("pool not empty", err)
	}
	for {
		raw, queryErr := run(ctx, "incus", "query", "--raw", "/1.0/operations?recursion=1&all-projects=true")
		if queryErr != nil {
			t.Fatal(queryErr)
		}
		var response struct {
			Metadata map[string][]json.RawMessage `json:"metadata"`
		}
		if json.Unmarshal(raw, &response) != nil {
			t.Fatal("empty-pool response invalid")
		}
		if len(response.Metadata) == 0 {
			if !compatOperationsIdle(raw) {
				t.Fatal("real empty envelope rejected")
			}
			plain, queryErr := run(ctx, "incus", "query", "/1.0/operations?recursion=1&all-projects=true")
			if queryErr != nil || len(strings.TrimSpace(string(plain))) != 0 {
				t.Fatal("real suppressed empty query response", queryErr)
			}
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("fixture setup operations did not settle")
		case <-time.After(time.Second):
		}
	}
	p := &CompatPermit{RequestID: "11111111-1111-4111-8111-111111111111", HostIdentity: strings.Repeat("a", 64), ExpiresAt: time.Now().Add(240 * time.Second).UTC().Format(time.RFC3339Nano)}
	oldBinary, err := os.ReadFile("/usr/sbin/incusd")
	if err != nil {
		t.Fatal(err)
	}
	newBinary, err := compatibilityBinary()
	if err != nil {
		t.Fatal(err)
	}
	if compatHash(oldBinary) != compatHash(newBinary) {
		// Model an atomic publication that never reloaded the original daemon.
		// No customer is created and no database migration has been performed.
		if err = replaceCompatBinary(newBinary); err != nil {
			t.Fatal(err)
		}
		refusal := prepareIncusCompatibility(ctx, p)
		restore := replaceCompatBinary(oldBinary)
		if restore != nil {
			t.Fatal("restore unpublished fixture binary", restore)
		}
		if refusal == nil {
			t.Fatal("old running daemon accepted as activated new binary")
		}
		if _, err = os.Lstat(compatJournalPath); !os.IsNotExist(err) {
			t.Fatal("unloaded binary must not mint a verified compatibility journal", err)
		}
		t.Log("PASS real Incus: published candidate with original running inode is refused before activation receipt")
	}
	if err = prepareIncusCompatibility(ctx, p); err != nil {
		t.Fatal("empty pool automatic reload", err)
	}
	if err = prepareIncusCompatibility(ctx, p); err != nil {
		t.Fatal("empty pool idempotency", err)
	}
	status, request, _ := incusCompatibilityStatus(ctx)
	if status != "verified" || request != p.RequestID {
		t.Fatal("empty pool receipt missing")
	}
	if empty, err := localHostMaintenanceEmpty(ctx); err != nil || !empty {
		t.Fatal("actual all-projects empty inventory", err)
	}
	manifest, err := compatibilityMetadata()
	if err != nil {
		t.Fatal(err)
	}
	pid, err := compatStartingDaemon(ctx, "/run/incus/incusd.pid", "/usr/sbin/incusd", manifest.SHA256)
	if err != nil || pid < 2 {
		t.Fatal("exact activated daemon unavailable", pid, err)
	}
	start, err := compatProcessStart(pid)
	if err != nil {
		t.Fatal(err)
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		t.Fatal(err)
	}
	if err = process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err = waitCompatDaemonExit(ctx, pid, start); err != nil {
		t.Fatal(err)
	}
	status, request, _ = incusCompatibilityStatus(ctx)
	if status == "verified" || request != p.RequestID {
		t.Fatal("dead daemon inherited verified status", status, request)
	}
	if err = prepareIncusCompatibility(ctx, p); err != nil {
		t.Fatal("later daemon exit automatic recovery", err)
	}
	status, request, _ = incusCompatibilityStatus(ctx)
	if status != "verified" || request != p.RequestID {
		t.Fatal("same-permit daemon recovery not verified")
	}
	t.Log("PASS later exact daemon exit: stale status refused, original permit restarts same binary and verifies empty pool")
	// Replace only the same bytes of a real mapped host library in this
	// disposable root. The old daemon retains its deleted mapping until the
	// authorized graceful reload; no guest or library content is changed.
	library, err := filepath.EvalSymlinks("/usr/lib/liblxc.so.1")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(library)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(library)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.CreateTemp(filepath.Dir(library), ".incudal-library-fixture-*")
	if err != nil {
		t.Fatal(err)
	}
	if err = file.Chmod(info.Mode().Perm()); err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		t.Fatal("library fixture publication", err, closeErr)
	}
	if err = os.Rename(file.Name(), library); err != nil {
		t.Fatal(err)
	}
	status, request, _ = incusCompatibilityStatus(ctx)
	if status != "needed" || request != p.RequestID {
		t.Fatal("old mapped host library accepted as activated", status)
	}
	for n := 0; n < 2; n++ {
		if err = prepareIncusCompatibility(ctx, p); err != nil {
			t.Fatal("mapped host library automatic reload", err)
		}
	}
	status, request, _ = incusCompatibilityStatus(ctx)
	if status != "verified" || request != p.RequestID {
		t.Fatal("mapped library reload not confirmed", status)
	}
	t.Log("PASS actual mapped LXC library replacement: original permit graceful reloads same Incus binary; kernel peer and loaded code confirmed")
}
