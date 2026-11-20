//go:build linux

package provisioning

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"incudal-agent/internal/localincus"
)

type compatGuest struct {
	Name, Status string
	Config       map[string]string
}
type compatJournal struct {
	Version                 int
	OldHash, NewHash        string
	PID                     int
	ProcessStart            string
	RequestID, HostIdentity string
	Phase                   string
	Guests                  []compatGuest
}

const compatJournalPath = "/var/lib/incudal-agent/incus-compat.json"
const compatBackupPath = "/usr/sbin/incusd.incudal-before-sysinfo"

func validCompatPermit(p *CompatPermit) bool {
	if p == nil {
		return false
	}
	at, e := time.Parse(time.RFC3339Nano, p.ExpiresAt)
	if e != nil || !at.After(time.Now()) || !at.Before(time.Now().Add(5*time.Minute)) || !guestUUID.MatchString(p.RequestID) || len(p.HostIdentity) != 64 || len(p.Guests) > 1 {
		return false
	}
	for _, g := range p.Guests {
		if !guestName.MatchString(g.Name) || !guestUUID.MatchString(g.UUID) || (g.State != "Running" && g.State != "Stopped") {
			return false
		}
	}
	return true
}
func compatPermitGuests(p *CompatPermit, rows []compatGuest) bool {
	if len(p.Guests) != len(rows) {
		return false
	}
	for _, g := range p.Guests {
		found := false
		for _, r := range rows {
			if r.Name == g.Name && r.Config["volatile.uuid"] == g.UUID && r.Status == g.State {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func incusCompatibilityStatus(ctx context.Context) (string, string, string) {
	r, e := releaseFile()
	if e != nil || !strings.Contains(r, "ID=alpine") && !strings.Contains(r, "ID=\"alpine\"") {
		return "", "", ""
	}
	var j compatJournal
	if b, e := os.ReadFile(compatJournalPath); e == nil && json.Unmarshal(b, &j) == nil {
		if j.Phase == "reloading" || j.Phase == "prepared" || j.Phase == "rolling-back" {
			return "pending", j.RequestID, j.NewHash
		}
	}
	manifest, e := compatibilityMetadata()
	if e != nil {
		return "", "", ""
	}
	installedHash, e := hashCompatFile(ctx, "/usr/sbin/incusd")
	if e != nil {
		return "", "", ""
	}
	if installedHash == manifest.SHA256 {
		if j.Phase == "verified" {
			return "verified", j.RequestID, manifest.SHA256
		}
		return "needed", j.RequestID, manifest.SHA256
	}
	raw, e := run(ctx, "incus", "query", "/1.0")
	if e != nil {
		return "", "", ""
	}
	var server struct {
		Environment struct {
			ServerVersion string `json:"server_version"`
		}
	}
	if json.Unmarshal(raw, &server) != nil || server.Environment.ServerVersion != "7.0.1" {
		return "", "", ""
	}
	return "needed", j.RequestID, manifest.SHA256
}
func saveCompatJournal(v compatJournal) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(compatJournalPath), ".incus-compat-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	f.Close()
	if e != nil {
		return e
	}
	return os.Rename(f.Name(), compatJournalPath)
}
func compatGuests(ctx context.Context) ([]compatGuest, error) {
	b, e := run(ctx, "incus", "list", "--format=json")
	if e != nil {
		return nil, e
	}
	var rows []compatGuest
	if e = json.Unmarshal(b, &rows); e != nil {
		// Describe the parse failure without exposing guest configuration.
		return nil, fmt.Errorf("compatibility guest list invalid (bytes=%d): %w", len(b), e)
	}
	for _, r := range rows {
		if !guestName.MatchString(r.Name) || !guestUUID.MatchString(r.Config["volatile.uuid"]) || r.Status != "Running" && r.Status != "Stopped" {
			return nil, fmt.Errorf("compatibility guest state waiting")
		}
	}
	return rows, nil
}
func sameCompatGuests(a, b []compatGuest) bool {
	if len(a) != len(b) {
		return false
	}
	for _, x := range a {
		found := false
		for _, y := range b {
			if x.Name == y.Name && x.Status == y.Status && x.Config["volatile.uuid"] == y.Config["volatile.uuid"] {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// A newer expiry stop/delete may finish during a daemon reload. It cannot
// authorize a new guest or turn an originally stopped guest into Running.
func compatibleCurrentGuests(before, after []compatGuest) bool {
	for _, y := range after {
		found := false
		for _, x := range before {
			if x.Name == y.Name && x.Config["volatile.uuid"] == y.Config["volatile.uuid"] && (x.Status == y.Status || x.Status == "Running" && y.Status == "Stopped") {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func waitCompatDaemonExit(ctx context.Context, pid int, expectedStart string) error {
	for n := 0; n < 90; n++ {
		currentStart, readErr := compatProcessStart(pid)
		if readErr != nil || currentStart != expectedStart || syscall.Kill(pid, 0) != nil {
			return nil
		}
		if b, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); e == nil {
			at := strings.LastIndex(string(b), ") ")
			if at >= 0 && strings.HasPrefix(string(b)[at+2:], "Z ") {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return fmt.Errorf("compatibility graceful daemon exit waiting")
}

func compatProcessStart(pid int) (string, error) {
	b, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if e != nil {
		return "", e
	}
	s := string(b)
	at := strings.LastIndex(s, ") ")
	if at < 0 {
		return "", fmt.Errorf("compatibility process stat invalid")
	}
	f := strings.Fields(s[at+2:])
	if len(f) < 20 {
		return "", fmt.Errorf("compatibility process stat invalid")
	}
	return f[19], nil
}
func startCompatDaemon(ctx context.Context, expectedHash string) error {
	// A prior attempt may have started the daemon before its receipt was saved.
	// Reuse that process rather than launching a second backend for Incus.
	pid, err := compatStartingDaemon(ctx, "/run/incus/incusd.pid", "/usr/sbin/incusd", expectedHash)
	if err != nil {
		return err
	}
	// A service-start reply may arrive before its Unix socket. Never launch a
	// second daemon when its root-owned PID already names the expected binary.
	if pid > 0 {
		return waitCompatReady(ctx, expectedHash)
	}
	if err := retireExitedCompatPID(ctx, "/run/incus/incusd.pid", expectedHash); err != nil {
		return err
	}
	// The old OpenRC runlevel marker survives a SIGTERM daemon reload.
	// Clear only its stale marker after the exact original PID has exited.
	if _, e := run(ctx, "rc-service", "incusd", "zap"); e != nil {
		return fmt.Errorf("compatibility stale service marker: %w", e)
	}
	if _, e := run(ctx, "rc-service", "incusd", "start"); e != nil {
		return fmt.Errorf("compatibility daemon service start: %w", e)
	}
	return waitCompatReady(ctx, expectedHash)
}

func retireExitedCompatPID(ctx context.Context, path, expectedHash string) error {
	before, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !before.Mode().IsRegular() || before.Size() > 32 || before.Mode()&0022 != 0 || before.Sys().(*syscall.Stat_t).Uid != 0 {
		return fmt.Errorf("compatibility service PID receipt unsafe")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	// OpenRC tests only the pidfile's PID and may count an unreaped zombie as
	// already running. Retire only a safe, unchanged receipt whose process is
	// absent or a zombie; a live/reused PID remains a hard identity failure.
	pid, err := compatStartingDaemon(ctx, path, "/usr/sbin/incusd", expectedHash)
	if err != nil || pid != 0 {
		return fmt.Errorf("compatibility service receipt still active or changed")
	}
	after, err := os.Lstat(path)
	current, readErr := os.ReadFile(path)
	if err != nil || readErr != nil || !os.SameFile(before, after) || before.ModTime() != after.ModTime() || before.Sys().(*syscall.Stat_t).Ctim != after.Sys().(*syscall.Stat_t).Ctim || string(current) != string(data) {
		return fmt.Errorf("compatibility service receipt changed before retirement")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return os.Remove(path)
}

func compatStartingDaemon(ctx context.Context, pidPath, binaryPath, expectedHash string) (int, error) {
	info, err := os.Lstat(pidPath)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > 32 || info.Mode()&0022 != 0 || info.Sys().(*syscall.Stat_t).Uid != 0 {
		return 0, fmt.Errorf("compatibility service PID receipt unsafe")
	}
	data, err := os.ReadFile(pidPath)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid < 2 {
		return 0, fmt.Errorf("compatibility service PID receipt invalid")
	}
	process := fmt.Sprintf("/proc/%d", pid)
	start, err := compatProcessStart(pid)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	stat, err := os.ReadFile(process + "/stat")
	if err != nil {
		return 0, err
	}
	end := strings.LastIndex(string(stat), ") ")
	if end >= 0 && strings.HasPrefix(string(stat)[end+2:], "Z ") {
		return 0, nil
	}
	exe, err := os.Readlink(process + "/exe")
	if err != nil || exe != binaryPath || syscall.Kill(pid, 0) != nil {
		return 0, fmt.Errorf("compatibility service process changed")
	}
	f, err := os.Open(process + "/exe")
	if err != nil {
		return 0, err
	}
	hash, err := hashCompatReader(ctx, f)
	f.Close()
	currentStart, startErr := compatProcessStart(pid)
	if err != nil || startErr != nil || start != currentStart || hash != expectedHash {
		return 0, fmt.Errorf("compatibility service executable changed")
	}
	return pid, nil
}

func waitCompatReady(ctx context.Context, expectedHash string) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	for {
		if _, err := localincus.Query(ctx, "/internal/ready", true); err == nil {
			pid, err := compatStartingDaemon(ctx, "/run/incus/incusd.pid", "/usr/sbin/incusd", expectedHash)
			if err != nil {
				return err
			}
			raw, err := localincus.Query(ctx, "/1.0", false)
			var server struct {
				Environment struct {
					PID int `json:"server_pid"`
				} `json:"environment"`
			}
			if err == nil && json.Unmarshal(raw, &server) == nil && pid > 0 && server.Environment.PID == pid {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("compatibility daemon readiness not confirmed: %w", ctx.Err())
		case <-time.After(500 * time.Millisecond):
		}
	}
}
func prepareIncusCompatibility(ctx context.Context, permit *CompatPermit) error {
	if !validCompatPermit(permit) {
		return fmt.Errorf("compatibility permit expired")
	}
	release, e := releaseFile()
	if e != nil {
		return e
	}
	if !strings.Contains(release, "ID=alpine") && !strings.Contains(release, "ID=\"alpine\"") {
		return nil
	}
	unlock, e := lock()
	if e != nil {
		return e
	}
	defer unlock()
	var journal compatJournal
	if b, readErr := os.ReadFile(compatJournalPath); readErr == nil {
		if json.Unmarshal(b, &journal) != nil || journal.Version != 1 || len(journal.OldHash) != 64 || len(journal.NewHash) != 64 || journal.PID < 2 || journal.ProcessStart == "" || !strings.Contains("|prepared|reloading|verified|rolling-back|rolled-back|", "|"+journal.Phase+"|") {
			return fmt.Errorf("compatibility journal invalid")
		}
	} else if !os.IsNotExist(readErr) {
		return readErr
	}
	if journal.Phase != "" && (journal.RequestID != permit.RequestID || journal.HostIdentity != permit.HostIdentity) {
		return fmt.Errorf("compatibility journal authority changed")
	}
	if journal.Phase == "rolling-back" {
		return rollbackIncusCompatibility(ctx, journal)
	}
	if journal.Phase == "prepared" {
		oldHash, e := hashCompatFile(ctx, compatBackupPath)
		if e != nil || oldHash != journal.OldHash {
			return fmt.Errorf("compatibility prepared rollback invalid")
		}
		if e = copyCompatFile(ctx, compatBackupPath, "/usr/sbin/incusd", journal.OldHash, true); e != nil {
			return e
		}
		journal.Phase = "rolled-back"
		return saveCompatJournal(journal)
	}
	if journal.Phase == "reloading" {
		if start, e := compatProcessStart(journal.PID); e == nil && start == journal.ProcessStart {
			if e = syscall.Kill(journal.PID, syscall.SIGTERM); e != nil {
				return e
			}
		}
		if e = waitCompatDaemonExit(ctx, journal.PID, journal.ProcessStart); e != nil {
			return e
		}
		installedHash, e := hashCompatFile(ctx, "/usr/sbin/incusd")
		if e != nil || installedHash != journal.NewHash {
			return fmt.Errorf("compatibility reloading binary changed")
		}
		if e = startCompatDaemon(ctx, journal.NewHash); e != nil {
			return rollbackIncusCompatibility(ctx, journal)
		}
		rows, e := compatGuests(ctx)
		if e != nil || !compatibleCurrentGuests(journal.Guests, rows) {
			return fmt.Errorf("compatibility guest baseline not confirmed")
		}
		journal.Phase = "verified"
		return saveCompatJournal(journal)
	}
	if journal.Phase == "verified" {
		installedHash, e := hashCompatFile(ctx, "/usr/sbin/incusd")
		if e != nil {
			return e
		}
		if installedHash != journal.NewHash {
			return fmt.Errorf("compatibility installed daemon drifted")
		}
		manifest, e := compatibilityMetadata()
		if e != nil {
			return e
		}
		if manifest.SHA256 == journal.NewHash {
			return nil
		}
		// Keep the previous rollback file immutable before a new repair generation.
		if oldHash, readErr := hashCompatFile(ctx, compatBackupPath); readErr == nil {
			if oldHash != journal.OldHash {
				return fmt.Errorf("previous compatibility rollback changed")
			}
			archive := compatBackupPath + "." + journal.NewHash
			if savedHash, readErr := hashCompatFile(ctx, archive); readErr == nil {
				if savedHash != journal.OldHash {
					return fmt.Errorf("previous rollback archive changed")
				}
				if e = os.Remove(compatBackupPath); e != nil {
					return e
				}
			} else if os.IsNotExist(readErr) {
				if e = os.Rename(compatBackupPath, archive); e != nil {
					return e
				}
			} else {
				return readErr
			}
		} else if !os.IsNotExist(readErr) {
			return readErr
		}
		journal = compatJournal{}
	}
	info, e := run(ctx, "incus", "query", "/1.0")
	if e != nil {
		return e
	}
	var server struct {
		Environment struct {
			ServerVersion string `json:"server_version"`
		}
	}
	if json.Unmarshal(info, &server) != nil {
		return fmt.Errorf("compatibility server read invalid")
	}
	if server.Environment.ServerVersion != "7.0.1" {
		return nil
	}
	manifest, e := compatibilityMetadata()
	if e != nil {
		return e
	}
	installedHash, e := hashCompatFile(ctx, "/usr/sbin/incusd")
	if e != nil {
		return e
	}
	if installedHash == manifest.SHA256 {
		rows, e := compatGuests(ctx)
		if e != nil {
			return e
		}
		pidData, e := os.ReadFile("/run/incus/incusd.pid")
		if e != nil {
			return e
		}
		pid, e := strconv.Atoi(strings.TrimSpace(string(pidData)))
		if e != nil {
			return e
		}
		start, e := compatProcessStart(pid)
		if e != nil {
			return e
		}
		return saveCompatJournal(compatJournal{Version: 1, OldHash: installedHash, NewHash: manifest.SHA256, PID: pid, ProcessStart: start, RequestID: permit.RequestID, HostIdentity: permit.HostIdentity, Phase: "verified", Guests: rows})
	}
	operations, e := run(ctx, "incus", "query", "--raw", "/1.0/operations?recursion=1")
	if e != nil {
		return e
	}
	if !compatOperationsIdle(operations) {
		return fmt.Errorf("compatibility waits for active operations")
	}
	guests, e := compatGuests(ctx)
	if e != nil {
		return e
	}
	if !compatPermitGuests(permit, guests) || !validCompatPermit(permit) {
		return fmt.Errorf("compatibility current guest authority changed")
	}
	pidData, e := os.ReadFile("/run/incus/incusd.pid")
	if e != nil {
		return e
	}
	pid, e := strconv.Atoi(strings.TrimSpace(string(pidData)))
	if e != nil || pid < 2 {
		return fmt.Errorf("compatibility daemon identity missing")
	}
	processStart, e := compatProcessStart(pid)
	if e != nil {
		return fmt.Errorf("compatibility daemon process unavailable")
	}
	executablePath := fmt.Sprintf("/proc/%d/exe", pid)
	exe, e := os.Readlink(executablePath)
	if e != nil || strings.TrimSuffix(exe, " (deleted)") != "/usr/sbin/incusd" {
		return fmt.Errorf("compatibility daemon changed")
	}
	// A prepared recovery atomically restores the original file while the
	// original daemon still holds its unlinked inode. Compare that process's
	// actual executable, never treat a matching pathname as sufficient.
	executable, e := os.Open(executablePath)
	if e != nil {
		return fmt.Errorf("compatibility daemon executable unavailable")
	}
	runningHash, e := hashCompatReader(ctx, executable)
	executable.Close()
	currentStart, startErr := compatProcessStart(pid)
	if e != nil || startErr != nil || currentStart != processStart || runningHash != installedHash {
		return fmt.Errorf("compatibility original daemon content changed")
	}
	if s, e := os.Lstat("/usr/sbin/incusd"); e != nil || !s.Mode().IsRegular() || s.Mode()&0022 != 0 || s.Sys().(*syscall.Stat_t).Uid != 0 {
		return fmt.Errorf("compatibility original binary unsafe")
	}
	staged, e := stageCompatibilityBinary(ctx)
	if e != nil {
		return e
	}
	defer os.Remove(staged)
	_, e = run(ctx, "ldd", staged)
	if e != nil {
		return fmt.Errorf("compatibility libraries unavailable")
	}
	if journal.Phase == "rolled-back" {
		backupHash, e := hashCompatFile(ctx, compatBackupPath)
		if e != nil || backupHash != journal.OldHash || installedHash != journal.OldHash {
			return fmt.Errorf("compatibility original rollback changed")
		}
		if e = os.Remove(compatBackupPath); e != nil {
			return e
		}
	}
	if e = copyCompatFile(ctx, "/usr/sbin/incusd", compatBackupPath, installedHash, false); e != nil {
		return e
	}
	start, e := compatProcessStart(pid)
	if e != nil {
		return e
	}
	journal = compatJournal{Version: 1, OldHash: installedHash, NewHash: manifest.SHA256, PID: pid, ProcessStart: start, RequestID: permit.RequestID, HostIdentity: permit.HostIdentity, Phase: "prepared", Guests: guests}
	if e = saveCompatJournal(journal); e != nil {
		return e
	}
	// ldd may succeed on a changed file. Bind the exact staged bytes again
	// before the atomic replacement; no unverified content reaches the daemon.
	stagedHash, e := hashCompatFile(ctx, staged)
	if e != nil || stagedHash != manifest.SHA256 {
		return fmt.Errorf("compatibility staged binary changed")
	}
	if e = os.Rename(staged, "/usr/sbin/incusd"); e != nil {
		return e
	}
	journal.Phase = "reloading"
	if e = saveCompatJournal(journal); e != nil {
		return e
	}
	if current, e := compatProcessStart(pid); e != nil || current != start {
		return fmt.Errorf("compatibility daemon process changed")
	}
	if !validCompatPermit(permit) {
		return fmt.Errorf("compatibility permit expired before reload")
	}
	if e = syscall.Kill(pid, syscall.SIGTERM); e != nil {
		return e
	}
	if e = waitCompatDaemonExit(ctx, pid, start); e != nil {
		return e
	}
	if e = startCompatDaemon(ctx, journal.NewHash); e != nil {
		return rollbackIncusCompatibility(ctx, journal)
	}
	rows, e := compatGuests(ctx)
	if e != nil || !compatibleCurrentGuests(guests, rows) {
		return fmt.Errorf("compatibility guest baseline not confirmed")
	}
	journal.Phase = "verified"
	return saveCompatJournal(journal)
}
func compatOperationsIdle(response []byte) bool {
	var envelope struct {
		Type       string                       `json:"type"`
		StatusCode int                          `json:"status_code"`
		Error      string                       `json:"error"`
		Metadata   map[string][]json.RawMessage `json:"metadata"`
	}
	if json.Unmarshal(response, &envelope) != nil || envelope.Type != "sync" || envelope.StatusCode != 200 || envelope.Error != "" || envelope.Metadata == nil {
		return false
	}
	for _, rows := range envelope.Metadata {
		for _, raw := range rows {
			var operation struct {
				Status string `json:"status"`
			}
			if json.Unmarshal(raw, &operation) != nil || operation.Status != "Success" && operation.Status != "Failure" && operation.Status != "Cancelled" {
				return false
			}
		}
	}
	return true
}
func rollbackIncusCompatibility(ctx context.Context, journal compatJournal) error {
	backupHash, e := hashCompatFile(ctx, compatBackupPath)
	if e != nil || backupHash != journal.OldHash {
		return fmt.Errorf("compatibility rollback identity invalid")
	}
	journal.Phase = "rolling-back"
	if e = saveCompatJournal(journal); e != nil {
		return e
	}
	if e = copyCompatFile(ctx, compatBackupPath, "/usr/sbin/incusd", journal.OldHash, true); e != nil {
		return e
	}
	if e = startCompatDaemon(ctx, journal.OldHash); e != nil {
		return e
	}
	rows, e := compatGuests(ctx)
	if e != nil || !compatibleCurrentGuests(journal.Guests, rows) {
		return fmt.Errorf("compatibility rollback baseline pending")
	}
	journal.Phase = "rolled-back"
	if e = saveCompatJournal(journal); e != nil {
		return e
	}
	return fmt.Errorf("compatibility rolled back; retry pending")
}
