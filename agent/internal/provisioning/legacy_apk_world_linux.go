//go:build linux

package provisioning

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// The owner confirmed on 2026-11-24 that these exact historical constraints
// were written by our old installers, not by an administrator. Adopt only
// this reviewed Alpine 3.24 catalog, once per enrolled host. Later edits and
// every other constraint remain administrator-owned.
var legacyAlpineWorldVersions = map[string]string{
	"apparmor": "4.1.7-r1", "apparmor-openrc": "4.1.7-r1", "apparmor-utils": "4.1.7-r1",
	"apparmor-profiles-abstractions": "4.1.7-r1", "apparmor-profiles-api": "4.1.7-r1", "apparmor-profiles-tunables": "4.1.7-r1",
	"libapparmor": "4.1.7-r1", "py3-apparmor": "4.1.7-r1", "py3-apparmor-pyc": "4.1.7-r1",
	"btrfs-progs-extra": "6.17.1-r1", "device-mapper": "2.03.35-r3", "device-mapper-event-libs": "2.03.35-r3",
	"fuse3-libs": "3.18.3-r0", "libaio": "0.3.113-r2", "lua-lunix": "20190403-r0", "lua-optarg": "0.4-r1",
	"lua5.5": "5.5.0-r1", "lua5.5-libs": "5.5.0-r1", "lua5.5-optarg": "0.4-r1",
	"lvm2": "2.03.35-r2", "lvm2-extra": "2.03.35-r2", "lvm2-libs": "2.03.35-r2", "lvm2-openrc": "2.03.35-r2",
	"lxc-lvm": "7.0.0-r0", "lxcfs": "6.0.1-r1", "lxcfs-openrc": "6.0.1-r1", "perl": "5.42.3-r0", "uidmapshift": "0.1.0-r0",
}

type legacyWorldReceipt struct {
	Version      int               `json:"version"`
	Recipe       string            `json:"recipe"`
	Node         string            `json:"node"`
	Architecture string            `json:"architecture"`
	Branch       string            `json:"branch"`
	Phase        string            `json:"phase"`
	Before       string            `json:"before"`
	After        string            `json:"after"`
	BeforeHash   string            `json:"beforeHash"`
	AfterHash    string            `json:"afterHash"`
	Mode         uint32            `json:"mode"`
	Packages     map[string]string `json:"packages"`
}

const legacyWorldRecipe = "legacy-apk-world-owner-20261124-v1"

var legacyWorldAtom = regexp.MustCompile(`^[a-zA-Z0-9+_.-]+(?:@[a-zA-Z0-9_.-]+)?(?:[=~<>]{1,2}[0-9][a-zA-Z0-9+_.:~*-]*)?$`)

func legacyWorldHash(value string) string {
	valueHash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(valueHash[:])
}

func legacyWorldPlan(before string, installed map[string]string) (string, error) {
	if len(before) > 65536 || strings.ContainsAny(before, "\x00\r") || len(installed) == 0 || len(installed) > 8192 {
		return "", fmt.Errorf("legacy package constraints invalid")
	}
	for name, version := range installed {
		if match := installedSecurityPackage.FindStringSubmatch(name + "-" + version); match == nil || match[1] != name || match[2] != version {
			return "", fmt.Errorf("legacy package inventory invalid")
		}
	}
	lines := strings.SplitAfter(before, "\n")
	seen := map[string]bool{}
	for _, line := range lines {
		atom := strings.TrimSuffix(line, "\n")
		if atom == "" || strings.HasPrefix(atom, "#") {
			continue
		}
		if !legacyWorldAtom.MatchString(atom) {
			return "", fmt.Errorf("legacy package constraint syntax invalid")
		}
		name := strings.FieldsFunc(atom, func(r rune) bool { return strings.ContainsRune("@=~<>", r) })
		if len(name) == 0 || seen[name[0]] {
			return "", fmt.Errorf("legacy package constraints ambiguous")
		}
		seen[name[0]] = true
	}
	for i, line := range lines {
		atom := strings.TrimSuffix(line, "\n")
		name, version, exact := strings.Cut(atom, "=")
		legacyVersion, known := legacyAlpineWorldVersions[name]
		if exact && known && legacyVersion == version && installed[name] == version {
			// Keep the installed package required by world; only its old exact
			// version constraint changes, never the package itself.
			lines[i] = name + strings.TrimPrefix(line, atom)
		}
	}
	return strings.Join(lines, ""), nil
}

func readLegacyWorldFile(path string, private bool) ([]byte, os.FileMode, error) {
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode()&0022 != 0 || info.Sys().(*syscall.Stat_t).Uid != 0 {
			return nil, 0, fmt.Errorf("legacy package directory unsafe")
		}
		if dir == "/" {
			break
		}
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, 0, err
	}
	file := os.NewFile(uintptr(fd), "legacy-world")
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 262144 || info.Sys().(*syscall.Stat_t).Uid != 0 || info.Sys().(*syscall.Stat_t).Nlink != 1 || info.Mode()&0022 != 0 || private && info.Mode()&0077 != 0 {
		return nil, 0, fmt.Errorf("legacy package file unsafe")
	}
	data, err := io.ReadAll(io.LimitReader(file, 262145))
	if err != nil || len(data) > 262144 {
		return nil, 0, fmt.Errorf("legacy package file limit exceeded")
	}
	return data, info.Mode().Perm(), nil
}

func writeLegacyWorldFile(path string, data []byte, mode os.FileMode, expected []byte) error {
	if len(data) > 262144 {
		return fmt.Errorf("legacy package receipt size exceeded")
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".legacy-apk-world-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err = file.Chmod(mode); err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err == nil && expected != nil {
		current, currentMode, readErr := readLegacyWorldFile(path, false)
		if readErr != nil || string(current) != string(expected) || currentMode != mode {
			return fmt.Errorf("legacy package publication changed")
		}
	}
	if err == nil && expected == nil {
		if _, err := os.Lstat(path); err == nil {
			if _, _, err := readLegacyWorldFile(path, true); err != nil {
				return err
			}
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	if err == nil {
		err = os.Rename(file.Name(), path)
	}
	if err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func migrateLegacyWorldFiles(ctx context.Context, world, receiptPath, node, branch string, inventory func() (map[string]string, error)) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !guestUUID.MatchString(node) || branch != "3.24" {
		return fmt.Errorf("legacy package enrollment unsupported")
	}
	before, mode, err := readLegacyWorldFile(world, false)
	if err != nil {
		return err
	}
	if mode != 0600 && mode != 0640 && mode != 0644 {
		return fmt.Errorf("legacy package mode unsupported")
	}
	var receipt legacyWorldReceipt
	data, _, err := readLegacyWorldFile(receiptPath, true)
	if err == nil {
		if json.Unmarshal(data, &receipt) != nil || receipt.Version != 1 || receipt.Recipe != legacyWorldRecipe || receipt.Node != node || receipt.Architecture != runtime.GOARCH || receipt.Branch != branch || (receipt.Phase != "prepared" && receipt.Phase != "completed" && receipt.Phase != "preserved") || receipt.BeforeHash != legacyWorldHash(receipt.Before) || receipt.AfterHash != legacyWorldHash(receipt.After) || (receipt.Mode != 0600 && receipt.Mode != 0640 && receipt.Mode != 0644) || len(receipt.Packages) > 8192 {
			return fmt.Errorf("legacy package receipt invalid")
		}
		after, planErr := legacyWorldPlan(receipt.Before, receipt.Packages)
		if planErr != nil || after != receipt.After {
			return fmt.Errorf("legacy package receipt plan changed")
		}
		// Migration is one-time adoption, not a recurring pin remover. A later
		// administrator can restore even the identical old constraint.
		if receipt.Phase != "prepared" {
			return nil
		}
	} else if !os.IsNotExist(err) {
		return err
	} else {
		packages, err := inventory()
		if err != nil {
			return err
		}
		after, err := legacyWorldPlan(string(before), packages)
		if err != nil {
			return err
		}
		receipt = legacyWorldReceipt{Version: 1, Recipe: legacyWorldRecipe, Node: node, Architecture: runtime.GOARCH, Branch: branch, Phase: "prepared", Before: string(before), After: after, BeforeHash: legacyWorldHash(string(before)), AfterHash: legacyWorldHash(after), Mode: uint32(mode), Packages: packages}
		if receipt.Before == receipt.After {
			receipt.Phase = "completed"
		}
		data, _ = json.Marshal(receipt)
		if err := writeLegacyWorldFile(receiptPath, data, 0600, nil); err != nil {
			return err
		}
	}
	if receipt.Phase == "completed" {
		return nil
	}
	currentWorld, currentMode, readErr := readLegacyWorldFile(world, false)
	if readErr != nil {
		return readErr
	}
	if string(currentWorld) != receipt.Before && string(currentWorld) != receipt.After || uint32(currentMode) != receipt.Mode {
		// Another writer changed the file after planning. Preserve its bytes
		// and the original evidence rather than repeatedly replacing its pins.
		receipt.Phase = "preserved"
	} else if string(currentWorld) == receipt.Before {
		packages, err := inventory()
		if err != nil || !reflect.DeepEqual(packages, receipt.Packages) {
			return fmt.Errorf("legacy package inventory changed")
		}
		current, currentMode, err := readLegacyWorldFile(world, false)
		if err != nil || string(current) != receipt.Before || uint32(currentMode) != receipt.Mode || ctx.Err() != nil {
			return fmt.Errorf("legacy package publication changed")
		}
		if err := writeLegacyWorldFile(world, []byte(receipt.After), mode, []byte(receipt.Before)); err != nil {
			return err
		}
		receipt.Phase = "completed"
	} else {
		// The atomic world publication succeeded but its reply/receipt was lost.
		receipt.Phase = "completed"
	}
	data, _ = json.Marshal(receipt)
	return writeLegacyWorldFile(receiptPath, data, 0600, nil)
}

func validLegacyWorldPermit(p *LegacyWorldPermit) bool {
	if p == nil || p.Recipe != legacyWorldRecipe || !guestUUID.MatchString(p.Node) {
		return false
	}
	at, err := time.Parse(time.RFC3339Nano, p.ExpiresAt)
	return err == nil && at.After(time.Now()) && !at.After(time.Now().Add(5*time.Minute))
}

func migrateLegacyAlpineWorld(ctx context.Context, permit *LegacyWorldPermit) error {
	if !validLegacyWorldPermit(permit) {
		return fmt.Errorf("legacy package authority required")
	}
	release, err := os.ReadFile("/etc/alpine-release")
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !regexp.MustCompile(`^3\.24\.`).MatchString(strings.TrimSpace(string(release))) {
		return nil // no reviewed historical constraints on other branches
	}
	repositories, _, err := readLegacyWorldFile("/etc/apk/repositories", false)
	if err != nil {
		return err
	}
	if _, err := reviewedSecurityRepositories(string(release), string(repositories)); err != nil {
		return err // custom/tagged sources never acquire historical ownership
	}
	maintenance, _, readErr := readLegacyWorldFile("/var/lib/incudal-hardening/maintenance.json", false)
	if readErr == nil {
		var state struct {
			Phase string `json:"phase"`
		}
		if json.Unmarshal(maintenance, &state) != nil || (state.Phase != "customers-restored" && state.Phase != "rolled-back") {
			return fmt.Errorf("legacy package migration waits for previous maintenance")
		}
	} else if !os.IsNotExist(readErr) {
		return readErr
	}
	unlock, err := lock()
	if err != nil {
		return err
	}
	defer unlock()
	// Share apk's actual database lock; our Agent lock alone does not exclude
	// an administrator's concurrent package transaction.
	for _, dir := range []string{"/lib", "/lib/apk", "/lib/apk/db"} {
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode()&0022 != 0 || info.Sys().(*syscall.Stat_t).Uid != 0 {
			return fmt.Errorf("legacy package database unsafe")
		}
	}
	fd, err := syscall.Open("/lib/apk/db/lock", syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	databaseLock := os.NewFile(uintptr(fd), "apk-database-lock")
	defer databaseLock.Close()
	info, err := databaseLock.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0077 != 0 || info.Sys().(*syscall.Stat_t).Uid != 0 || info.Sys().(*syscall.Stat_t).Nlink != 1 {
		return fmt.Errorf("legacy package database lock unsafe")
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("legacy package database busy")
	}
	defer syscall.Flock(fd, syscall.LOCK_UN)
	node, _, err := readLegacyWorldFile("/etc/incudal-onboarding-id", false)
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(node)) != permit.Node || !validLegacyWorldPermit(permit) {
		return fmt.Errorf("legacy package enrollment changed")
	}
	return migrateLegacyWorldFiles(ctx, "/etc/apk/world", "/var/lib/incudal-agent/legacy-apk-world-v1.json", strings.TrimSpace(string(node)), "3.24", func() (map[string]string, error) {
		if !validLegacyWorldPermit(permit) {
			return nil, fmt.Errorf("legacy package authority expired")
		}
		output, err := run(ctx, "apk", "info", "-v")
		if err != nil {
			return nil, err
		}
		return securityInstalledPackages(string(output))
	})
}
