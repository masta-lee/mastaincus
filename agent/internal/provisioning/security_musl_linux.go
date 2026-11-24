//go:build linux

package provisioning

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
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
	"sort"
	"strings"
	"syscall"
	"time"
)

var securityMuslGroup = []string{"musl", "musl-utils"}
var securityMuslVersion = regexp.MustCompile(`^1\.2\.(0|[1-9][0-9]*)-r(0|[1-9][0-9]*)$`)
var securityRuntimeHash = regexp.MustCompile(`^[a-f0-9]{64}$`)
var securityRuntimeCacheID = regexp.MustCompile(`^\.security-packages-[a-zA-Z0-9]+$`)
var securityRuntimeCacheName = regexp.MustCompile(`^[a-zA-Z0-9+_.-]{1,200}$`)
var securityRuntimeReinstallation = regexp.MustCompile(`(?m)^(?:\([0-9]+/[0-9]+\) )?Reinstalling ([a-zA-Z0-9+_.-]+) \(([0-9][a-zA-Z0-9+_.~-]*)\)$`)

const securityRuntimeRecipe = "empty-musl-runtime-v1"
const securityRuntimeReceiptPath = "/var/lib/incudal-agent/empty-runtime-packages.json"

func securityMuslTargets(targets []string) bool {
	for _, name := range targets {
		if name == "musl" || name == "musl-utils" {
			return true
		}
	}
	return false
}

func securityMuslPlan(before, expected map[string]string, targets []string) error {
	if !securityMuslTargets(targets) {
		return nil
	}
	selected := map[string]bool{}
	for _, name := range targets {
		selected[name] = true
	}
	if !selected["musl"] || !selected["musl-utils"] {
		return fmt.Errorf("musl maintenance requires the complete runtime group")
	}
	if before["musl"] == "" && before["musl-utils"] == "" {
		return nil
	}
	if !securityMuslVersion.MatchString(before["musl"]) || !securityMuslVersion.MatchString(expected["musl"]) {
		return fmt.Errorf("musl runtime series not reviewed")
	}
	for _, name := range securityMuslGroup {
		if before[name] != "" && (before[name] != before["musl"] || expected[name] != expected["musl"]) || before[name] == "" && expected[name] != "" {
			return fmt.Errorf("musl runtime group not aligned")
		}
	}
	return nil
}

type securityPackageConstraint struct {
	Path string
	Data []byte
	Mode os.FileMode
}

func readSecurityPackageConstraints(paths ...string) ([]securityPackageConstraint, error) {
	result := make([]securityPackageConstraint, 0, len(paths))
	for _, path := range paths {
		data, mode, err := readLegacyWorldFile(path, false)
		if err != nil {
			return nil, err
		}
		result = append(result, securityPackageConstraint{Path: path, Data: data, Mode: mode})
	}
	return result, nil
}

func verifySecurityPackageConstraints(before []securityPackageConstraint) error {
	for _, original := range before {
		data, mode, err := readLegacyWorldFile(original.Path, false)
		if err != nil || mode != original.Mode || !bytes.Equal(data, original.Data) {
			return fmt.Errorf("security package administrator constraints changed")
		}
	}
	return nil
}

type securityRuntimeEnvironment struct {
	HostIdentity string            `json:"hostIdentity"`
	Architecture string            `json:"architecture"`
	BootID       string            `json:"bootId"`
	Files        map[string]string `json:"files"`
	Modes        map[string]uint32 `json:"modes"`
	Targets      []string          `json:"targets"`
}

type securityRuntimeReceipt struct {
	Version        int                        `json:"version"`
	Recipe         string                     `json:"recipe"`
	Phase          string                     `json:"phase"`
	CheckedAt      string                     `json:"checkedAt"`
	Environment    securityRuntimeEnvironment `json:"environment"`
	Before         map[string]string          `json:"before"`
	Expected       map[string]string          `json:"expected"`
	Plan           string                     `json:"plan"`
	LoaderBefore   string                     `json:"loaderBefore"`
	LoaderExpected string                     `json:"loaderExpected"`
	CacheID        string                     `json:"cacheId"`
	CacheFiles     map[string]string          `json:"cacheFiles"`
}

func securityRuntimeSnapshot(hostIdentity string, targets []string, constraints []securityPackageConstraint) (securityRuntimeEnvironment, error) {
	if !securityRuntimeHash.MatchString(hostIdentity) || !securityMuslTargets(targets) {
		return securityRuntimeEnvironment{}, fmt.Errorf("musl runtime authority unavailable")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || !guestUUID.MatchString(strings.TrimSpace(string(boot))) {
		return securityRuntimeEnvironment{}, fmt.Errorf("musl runtime boot identity unavailable")
	}
	result := securityRuntimeEnvironment{HostIdentity: hostIdentity, Architecture: runtime.GOARCH, BootID: strings.TrimSpace(string(boot)), Files: map[string]string{}, Modes: map[string]uint32{}, Targets: append([]string(nil), targets...)}
	for _, file := range constraints {
		result.Files[file.Path] = legacyWorldHash(string(file.Data))
		result.Modes[file.Path] = uint32(file.Mode)
	}
	return result, nil
}

func securityRuntimeSameEnvironment(a, b securityRuntimeEnvironment) bool {
	// A prepared transaction may survive a power loss. New authority and local
	// vacancy are checked again; an installed receipt is reused only on its boot.
	a.BootID, b.BootID = "", ""
	return reflect.DeepEqual(a, b)
}

func securityRuntimeInventoryWithin(before, expected, current map[string]string) bool {
	if len(current) > len(expected) {
		return false
	}
	for name, version := range current {
		if version != before[name] && version != expected[name] || expected[name] == "" {
			return false
		}
	}
	for name, version := range before {
		if version == "" || current[name] == "" {
			return false
		}
	}
	return true
}

func securityRuntimeResumePlan(output string, current map[string]string, receipt *securityRuntimeReceipt) error {
	if !securityRuntimeInventoryWithin(receipt.Before, receipt.Expected, current) || strings.Contains(output, "Removing ") || strings.Contains(output, "Downgrading ") || strings.Contains(output, "Reinstalling ") || strings.Contains(output, "UNTRUSTED") {
		return fmt.Errorf("musl original package transaction changed")
	}
	changes := securityPackageVersionChange.FindAllStringSubmatch(output, -1)
	additions := securityPackageInstallation.FindAllStringSubmatch(output, -1)
	if strings.Count(output, "Upgrading ") != len(changes) || strings.Count(output, "Installing ") != len(additions) {
		return fmt.Errorf("musl original package plan format changed")
	}
	seen := map[string]bool{}
	for _, change := range changes {
		name := change[1]
		if seen[name] || current[name] != change[2] || receipt.Before[name] != change[2] || receipt.Expected[name] != change[3] || change[2] == change[3] {
			return fmt.Errorf("musl original package upgrade changed")
		}
		seen[name] = true
	}
	for _, addition := range additions {
		name := addition[1]
		if seen[name] || current[name] != "" || receipt.Before[name] != "" || receipt.Expected[name] != addition[2] {
			return fmt.Errorf("musl original package addition changed")
		}
		seen[name] = true
	}
	if !reflect.DeepEqual(receipt.Expected, securityExpectedPackages(current, output)) {
		return fmt.Errorf("musl original complete package plan changed")
	}
	return nil
}

func readSecurityRuntimeReceipt(path string) (*securityRuntimeReceipt, error) {
	data, _, err := readLegacyWorldFile(path, true)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var receipt securityRuntimeReceipt
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&receipt) != nil {
		return nil, fmt.Errorf("musl runtime receipt invalid")
	}
	canonical, err := json.Marshal(receipt)
	if err != nil || !bytes.Equal(data, canonical) || receipt.Version != 1 || receipt.Recipe != securityRuntimeRecipe || receipt.Phase != "prepared" && receipt.Phase != "installed" || !securityRuntimeHash.MatchString(receipt.LoaderBefore) || !securityRuntimeHash.MatchString(receipt.LoaderExpected) || len(receipt.Plan) > 131072 {
		return nil, fmt.Errorf("musl runtime receipt invalid")
	}
	e := receipt.Environment
	if !securityRuntimeHash.MatchString(e.HostIdentity) || e.Architecture != "amd64" && e.Architecture != "arm64" || !guestUUID.MatchString(e.BootID) || len(e.Files) != 3 || len(e.Modes) != 3 || len(e.Targets) > 128 || !securityMuslTargets(e.Targets) {
		return nil, fmt.Errorf("musl runtime receipt identity invalid")
	}
	for _, path := range []string{"/etc/alpine-release", "/etc/apk/repositories", "/etc/apk/world"} {
		if !securityRuntimeHash.MatchString(e.Files[path]) || e.Modes[path]&0022 != 0 || e.Modes[path]&^0777 != 0 {
			return nil, fmt.Errorf("musl runtime receipt configuration invalid")
		}
	}
	at, err := time.Parse(time.RFC3339Nano, receipt.CheckedAt)
	if err != nil || at.IsZero() || at.After(time.Now()) || receipt.CheckedAt != at.UTC().Format(time.RFC3339Nano) {
		return nil, fmt.Errorf("musl runtime receipt timestamp invalid")
	}
	if len(receipt.Before) == 0 || len(receipt.Before) > 8192 || len(receipt.Expected) > 8192 {
		return nil, fmt.Errorf("musl runtime receipt inventory invalid")
	}
	if receipt.Phase == "prepared" && (receipt.CacheID == "" || len(receipt.CacheFiles) == 0) || receipt.CacheID != "" && !securityRuntimeCacheID.MatchString(receipt.CacheID) || len(receipt.CacheFiles) > 256 {
		return nil, fmt.Errorf("musl runtime original package cache invalid")
	}
	for name, hash := range receipt.CacheFiles {
		if !validSecurityRuntimeCacheName(name) || !securityRuntimeHash.MatchString(hash) {
			return nil, fmt.Errorf("musl runtime original cache file invalid")
		}
	}
	for _, packages := range []map[string]string{receipt.Before, receipt.Expected} {
		for name, version := range packages {
			match := installedSecurityPackage.FindStringSubmatch(name + "-" + version)
			if match == nil || match[1] != name || match[2] != version {
				return nil, fmt.Errorf("musl runtime receipt package invalid")
			}
		}
	}
	if err := safeSecurityPackagePlanFor(receipt.Plan, receipt.Before, e.Targets); err != nil || !reflect.DeepEqual(receipt.Expected, securityExpectedPackages(receipt.Before, receipt.Plan)) || receipt.Before["musl"] == "" {
		return nil, fmt.Errorf("musl runtime receipt original plan invalid")
	}
	return &receipt, nil
}

func saveSecurityRuntimeReceipt(path string, receipt securityRuntimeReceipt) error {
	data, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	previous, err := readSecurityRuntimeReceipt(path)
	if err != nil {
		return err
	}
	var original []byte
	if previous != nil {
		original, err = json.Marshal(previous)
		if err != nil {
			return err
		}
		if previous.Phase == "installed" && !bytes.Equal(data, original) {
			if previous.Environment.HostIdentity != receipt.Environment.HostIdentity || previous.Environment.Architecture != receipt.Environment.Architecture {
				return fmt.Errorf("musl completed receipt identity changed")
			}
			// A later safe world/tool change needs a new signed plan, not a
			// permanent retry or a rewritten historical installation claim.
			archive := path + ".installed-" + legacyWorldHash(string(original)) + ".json"
			archived, mode, readErr := readLegacyWorldFile(archive, true)
			if os.IsNotExist(readErr) {
				if err := writeLegacyWorldFile(archive, original, 0600, nil); err != nil {
					return err
				}
			} else if readErr != nil || mode != 0600 || !bytes.Equal(archived, original) {
				return fmt.Errorf("musl completed receipt archive changed")
			}
		}
	}
	return writeLegacyWorldFile(path, data, 0600, original)
}

func confirmSecurityRuntimeReceipt(ctx context.Context, receipt securityRuntimeReceipt, environment securityRuntimeEnvironment, installed map[string]string, constraints []securityPackageConstraint) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !reflect.DeepEqual(receipt.Expected, installed) || !securityRuntimeSameEnvironment(receipt.Environment, environment) {
		return fmt.Errorf("musl original installation not confirmed")
	}
	if err := verifySecurityPackageConstraints(constraints); err != nil {
		return err
	}
	current, err := runSecurityPackageCommand(ctx, "confirm-inventory", "info", "-v")
	if err != nil {
		return err
	}
	packages, err := securityInstalledPackages(string(current))
	if err != nil || !reflect.DeepEqual(packages, receipt.Expected) {
		return fmt.Errorf("musl complete installed inventory changed before confirmation")
	}
	loader, err := hashSecurityMuslLoader(ctx)
	if err != nil || loader != receipt.LoaderExpected {
		return fmt.Errorf("musl installed loader differs from the signed original candidate")
	}
	if err := verifySecurityPackageConstraints(constraints); err != nil {
		return err
	}
	// This is an installation receipt, not proof that PID1 or every process has
	// loaded the new code. The independent host maps check remains authoritative.
	receipt.Phase = "installed"
	receipt.Environment = environment
	receipt.CheckedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return saveSecurityRuntimeReceipt(securityRuntimeReceiptPath, receipt)
}

func securityRuntimeReceiptState(receipt *securityRuntimeReceipt, environment securityRuntimeEnvironment, installed map[string]string, loader string, now time.Time) (bool, error) {
	if receipt == nil {
		return false, nil
	}
	if receipt.Phase == "prepared" {
		if !securityRuntimeSameEnvironment(receipt.Environment, environment) {
			return false, fmt.Errorf("musl original runtime configuration changed")
		}
		if !securityRuntimeInventoryWithin(receipt.Before, receipt.Expected, installed) {
			return false, fmt.Errorf("musl original installed package inventory changed")
		}
		// APK can publish files before its installed database, or the database
		// before every file is durable. Only these two original hashes are
		// resumable; the original signed cache repairs registered payloads.
		if loader != receipt.LoaderBefore && loader != receipt.LoaderExpected {
			return false, fmt.Errorf("musl original loader identity changed")
		}
		return false, nil
	}
	if receipt.Environment.HostIdentity != environment.HostIdentity || receipt.Environment.Architecture != environment.Architecture {
		return false, fmt.Errorf("musl original runtime identity changed")
	}
	if loader != receipt.LoaderExpected || installed["musl"] != receipt.Expected["musl"] || installed["musl-utils"] != receipt.Expected["musl-utils"] {
		return false, fmt.Errorf("musl installed runtime changed outside the original transaction")
	}
	for _, mode := range environment.Modes {
		if mode&0022 != 0 || mode&^0777 != 0 {
			return false, fmt.Errorf("musl current runtime configuration unsafe")
		}
	}
	if !securityRuntimeSameEnvironment(receipt.Environment, environment) {
		// Normal tool repair can safely add a world atom after maintenance.
		// Keep its current constraints, obtain a new signed plan, and archive
		// the old installed receipt only when publishing the new transaction.
		return false, nil
	}
	at, err := time.Parse(time.RFC3339Nano, receipt.CheckedAt)
	if err != nil || now.Before(at) {
		return false, fmt.Errorf("musl runtime receipt timestamp invalid")
	}
	return receipt.Environment.BootID == environment.BootID && now.Sub(at) < 6*time.Hour && reflect.DeepEqual(installed, receipt.Expected), nil
}

func securityRuntimeReinstallPackages(receipt *securityRuntimeReceipt, installed map[string]string) ([]string, error) {
	if receipt == nil || receipt.Phase != "prepared" || !securityRuntimeInventoryWithin(receipt.Before, receipt.Expected, installed) {
		return nil, fmt.Errorf("musl original replay inventory unavailable")
	}
	names := []string{}
	for name, version := range receipt.Expected {
		if receipt.Before[name] != version && installed[name] == version {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, nil
}

func securityRuntimeReinstallPlan(output string, installed map[string]string, receipt *securityRuntimeReceipt, names []string) error {
	expectedNames, err := securityRuntimeReinstallPackages(receipt, installed)
	if err != nil || len(names) == 0 || !reflect.DeepEqual(names, expectedNames) {
		return fmt.Errorf("musl original registered replay changed")
	}
	for _, forbidden := range []string{"Installing ", "Upgrading ", "Removing ", "Purging ", "Downgrading ", "Replacing ", "Updating pinning", "UNTRUSTED", "ERROR:", "[APK unavailable, skipped]"} {
		if strings.Contains(output, forbidden) {
			return fmt.Errorf("musl original registered replay expanded")
		}
	}
	changes := securityRuntimeReinstallation.FindAllStringSubmatch(output, -1)
	if len(changes) != len(names) || strings.Count(output, "Reinstalling ") != len(changes) {
		return fmt.Errorf("musl original registered replay incomplete")
	}
	seen := map[string]bool{}
	for _, change := range changes {
		name := change[1]
		if seen[name] || installed[name] != change[2] || receipt.Expected[name] != change[2] || receipt.Before[name] == change[2] {
			return fmt.Errorf("musl original registered package changed")
		}
		seen[name] = true
	}
	for _, name := range names {
		if !seen[name] {
			return fmt.Errorf("musl original registered replay omitted package")
		}
	}
	return nil
}

func securityMuslLoaderPath() (string, error) {
	switch runtime.GOARCH {
	case "amd64":
		return "/lib/ld-musl-x86_64.so.1", nil
	case "arm64":
		return "/lib/ld-musl-aarch64.so.1", nil
	default:
		return "", fmt.Errorf("musl runtime architecture unsupported")
	}
}

func validSecurityRuntimeCacheName(name string) bool {
	if strings.HasPrefix(name, "musl-candidate/") {
		name = strings.TrimPrefix(name, "musl-candidate/")
	}
	return securityRuntimeCacheName.MatchString(name) && name != "." && name != ".."
}

func hashSecurityRuntimeCacheFile(ctx context.Context, path string) (string, int64, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return "", 0, err
	}
	file := os.NewFile(uintptr(fd), "runtime-package-cache")
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > 67108864 || before.Mode()&0022 != 0 || before.Sys().(*syscall.Stat_t).Uid != 0 || before.Sys().(*syscall.Stat_t).Nlink != 1 {
		return "", 0, fmt.Errorf("musl runtime cache file unsafe")
	}
	hash := sha256.New()
	n, err := copyCompatBytes(ctx, hash, file, before.Size())
	after, statErr := file.Stat()
	if err != nil || statErr != nil || n != before.Size() || !os.SameFile(before, after) || before.Size() != after.Size() || before.ModTime() != after.ModTime() || before.Sys().(*syscall.Stat_t).Ctim != after.Sys().(*syscall.Stat_t).Ctim {
		return "", 0, fmt.Errorf("musl runtime cache file changed during read")
	}
	// Root ownership/link checks above are not serialized permission claims.
	// Bind the actual file content, size and original permission bits together.
	digest := legacyWorldHash(fmt.Sprintf("%o:%d:%s", before.Mode().Perm(), before.Size(), hex.EncodeToString(hash.Sum(nil))))
	return digest, before.Size(), nil
}

func securityRuntimeCacheSnapshot(ctx context.Context, directory string) (map[string]string, error) {
	if filepath.Dir(directory) != "/var/lib/incudal-agent" || !securityRuntimeCacheID.MatchString(filepath.Base(directory)) {
		return nil, fmt.Errorf("musl runtime original cache path invalid")
	}
	for parent := filepath.Dir(directory); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&0022 != 0 || info.Sys().(*syscall.Stat_t).Uid != 0 {
			return nil, fmt.Errorf("musl runtime original cache parent unsafe")
		}
		if parent == "/" {
			break
		}
	}
	result := map[string]string{}
	var total int64
	for _, relative := range []string{"", "musl-candidate"} {
		path := filepath.Join(directory, relative)
		info, err := os.Lstat(path)
		if os.IsNotExist(err) && relative != "" {
			continue
		}
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || info.Sys().(*syscall.Stat_t).Uid != 0 {
			return nil, fmt.Errorf("musl runtime original cache directory unsafe")
		}
		files, err := os.ReadDir(path)
		if err != nil || len(files) > 256 {
			return nil, fmt.Errorf("musl runtime original cache inventory invalid")
		}
		for _, file := range files {
			if relative == "" && file.Name() == "musl-candidate" && file.IsDir() {
				continue
			}
			name := filepath.Join(relative, file.Name())
			if !validSecurityRuntimeCacheName(name) || !file.Type().IsRegular() || len(result) >= 256 {
				return nil, fmt.Errorf("musl runtime original cache entry invalid")
			}
			hash, size, err := hashSecurityRuntimeCacheFile(ctx, filepath.Join(directory, name))
			total += size
			if err != nil || total > 268435456 {
				return nil, fmt.Errorf("musl runtime original cache verification failed")
			}
			result[name] = hash
		}
	}
	if result["repositories"] == "" || len(result) == 1 {
		return nil, fmt.Errorf("musl runtime original signed indexes unavailable")
	}
	return result, nil
}

func verifySecurityRuntimeCache(ctx context.Context, receipt *securityRuntimeReceipt) (string, error) {
	if receipt == nil || !securityRuntimeCacheID.MatchString(receipt.CacheID) {
		return "", fmt.Errorf("musl runtime original cache receipt unavailable")
	}
	path := filepath.Join("/var/lib/incudal-agent", receipt.CacheID)
	files, err := securityRuntimeCacheSnapshot(ctx, path)
	if err != nil || !reflect.DeepEqual(files, receipt.CacheFiles) {
		return "", fmt.Errorf("musl runtime original signed cache changed")
	}
	return path, nil
}

func cacheSecurityRuntimePlan(ctx context.Context, base []string, before, expected map[string]string) error {
	dependencies := []string{}
	for name, version := range expected {
		if before[name] != version {
			dependencies = append(dependencies, name+"="+version)
		}
	}
	if len(dependencies) == 0 {
		return nil
	}
	sort.Strings(dependencies)
	// APK downloads and signature-checks its own cache filenames. Keep those
	// exact indexes/artifacts for an offline original-plan replay after a power
	// loss or interrupted installation, even if the upstream revision vanishes.
	_, err := runSecurityPackageCommand(ctx, "original-cache-fetch", append(append(append([]string(nil), base...), "cache", "download", "--upgrade"), dependencies...)...)
	return err
}

func hashSecurityMuslLoader(ctx context.Context) (string, error) {
	path, err := securityMuslLoaderPath()
	if err != nil {
		return "", err
	}
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode()&0022 != 0 || info.Sys().(*syscall.Stat_t).Uid != 0 {
			return "", fmt.Errorf("musl runtime loader directory unsafe")
		}
		if dir == "/" {
			break
		}
	}
	return hashCompatFile(ctx, path)
}

// Parse only a signature-verified APK v2 archive. Nothing is extracted to the
// host filesystem. The exact package/version/architecture and one root-owned
// executable loader are bound before any installation can replace that file.
func securityMuslArchiveLoader(ctx context.Context, source io.Reader, version, architecture string) (string, error) {
	if !securityMuslVersion.MatchString(version) || architecture != "x86_64" && architecture != "aarch64" {
		return "", fmt.Errorf("musl candidate identity invalid")
	}
	loader := "lib/ld-musl-" + architecture + ".so.1"
	reader := bufio.NewReader(io.LimitReader(source, 8388609))
	metadata, digest := "", ""
	entries, members := 0, 0
	for {
		if _, err := reader.Peek(1); err == io.EOF {
			break
		} else if err != nil {
			return "", err
		}
		members++
		if members > 4 || ctx.Err() != nil {
			return "", fmt.Errorf("musl candidate archive budget exceeded")
		}
		compressed, err := gzip.NewReader(reader)
		if err != nil {
			return "", fmt.Errorf("musl candidate archive format unsupported")
		}
		compressed.Multistream(false)
		limited := &io.LimitedReader{R: compressed, N: 16777217}
		archive := tar.NewReader(limited)
		for {
			header, err := archive.Next()
			if err == io.EOF {
				break
			}
			entries++
			if err != nil || entries > 256 || header.Size < 0 || header.Size > 8388608 || ctx.Err() != nil {
				compressed.Close()
				return "", fmt.Errorf("musl candidate archive invalid")
			}
			name := strings.TrimPrefix(header.Name, "./")
			if name == ".PKGINFO" {
				if metadata != "" || header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA || header.Size > 65536 {
					compressed.Close()
					return "", fmt.Errorf("musl candidate package metadata invalid")
				}
				data, err := io.ReadAll(archive)
				if err != nil {
					compressed.Close()
					return "", err
				}
				metadata = string(data)
			}
			if name == loader {
				if digest != "" || header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA || header.Uid != 0 || header.Gid != 0 || header.Mode&0022 != 0 || header.Mode&0111 == 0 || header.Size < 64 {
					compressed.Close()
					return "", fmt.Errorf("musl candidate loader file invalid")
				}
				hash := sha256.New()
				if n, err := copyCompatBytes(ctx, hash, archive, header.Size); err != nil || n != header.Size {
					compressed.Close()
					return "", fmt.Errorf("musl candidate loader read failed")
				}
				digest = hex.EncodeToString(hash.Sum(nil))
			}
		}
		_, err = io.Copy(io.Discard, limited)
		closeErr := compressed.Close()
		if err != nil || closeErr != nil || limited.N <= 0 {
			return "", fmt.Errorf("musl candidate archive checksum or limit invalid")
		}
	}
	fields := map[string]string{}
	for _, line := range strings.Split(metadata, "\n") {
		key, value, ok := strings.Cut(line, " = ")
		if !ok || key != "pkgname" && key != "pkgver" && key != "arch" && key != "origin" {
			continue
		}
		if fields[key] != "" {
			return "", fmt.Errorf("musl candidate package identity ambiguous")
		}
		fields[key] = value
	}
	if fields["pkgname"] != "musl" || fields["pkgver"] != version || fields["arch"] != architecture || fields["origin"] != "musl" || digest == "" {
		return "", fmt.Errorf("musl candidate package identity not confirmed")
	}
	return digest, nil
}

func fetchSecurityMuslLoader(ctx context.Context, base []string, cache, version string) (string, error) {
	if !securityMuslVersion.MatchString(version) {
		return "", fmt.Errorf("musl candidate version invalid")
	}
	directory := filepath.Join(cache, "musl-candidate")
	if err := os.Mkdir(directory, 0700); err != nil {
		return "", err
	}
	if _, err := runSecurityPackageCommand(ctx, "candidate-fetch", append(append([]string(nil), base...), "fetch", "--output", directory, "musl="+version)...); err != nil {
		return "", err
	}
	return verifyCachedSecurityMuslLoader(ctx, cache, version)
}

func verifyCachedSecurityMuslLoader(ctx context.Context, cache, version string) (string, error) {
	if !securityMuslVersion.MatchString(version) || filepath.Dir(cache) != "/var/lib/incudal-agent" || !securityRuntimeCacheID.MatchString(filepath.Base(cache)) {
		return "", fmt.Errorf("musl original candidate cache invalid")
	}
	directory := filepath.Join(cache, "musl-candidate")
	files, err := os.ReadDir(directory)
	if err != nil || len(files) != 1 || files[0].Name() != "musl-"+version+".apk" || !files[0].Type().IsRegular() {
		return "", fmt.Errorf("musl candidate package file unavailable")
	}
	file, err := openCompatFile(filepath.Join(directory, files[0].Name()))
	if err != nil {
		return "", err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || before.Size() > 8388608 {
		return "", fmt.Errorf("musl candidate package size invalid")
	}
	// Verify the same open file that the parser reads, not a second pathname.
	if output, err := runWithFiles(ctx, "apk", []*os.File{file}, "verify", "/proc/self/fd/3"); err != nil {
		return "", securityPackageCommandFailure("candidate-verify", output, err)
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	arch := "x86_64"
	if runtime.GOARCH == "arm64" {
		arch = "aarch64"
	}
	hash, err := securityMuslArchiveLoader(ctx, file, version, arch)
	after, statErr := file.Stat()
	if err != nil || statErr != nil || !os.SameFile(before, after) || before.Size() != after.Size() || before.ModTime() != after.ModTime() || before.Sys().(*syscall.Stat_t).Ctim != after.Sys().(*syscall.Stat_t).Ctim {
		return "", fmt.Errorf("musl candidate package changed during verification")
	}
	return hash, nil
}

func repairSecurityRuntimeRegisteredFiles(ctx context.Context, receipt *securityRuntimeReceipt, environment securityRuntimeEnvironment, installed map[string]string, loaderBefore string, constraints []securityPackageConstraint, authorize func(context.Context) error, install func(context.Context, []string) error) error {
	names, err := securityRuntimeReinstallPackages(receipt, installed)
	if err != nil || len(names) == 0 {
		return err
	}
	if authorize == nil || install == nil || ctx.Err() != nil {
		return fmt.Errorf("musl original registered replay authority unavailable")
	}
	if _, err := securityRuntimeReceiptState(receipt, environment, installed, loaderBefore, time.Now()); err != nil {
		return err
	}
	if err := authorize(ctx); err != nil {
		return err
	}
	cache, err := verifySecurityRuntimeCache(ctx, receipt)
	if err != nil {
		return err
	}
	loaderExpected, err := verifyCachedSecurityMuslLoader(ctx, cache, receipt.Expected["musl"])
	if err != nil || loaderExpected != receipt.LoaderExpected {
		return fmt.Errorf("musl original replay candidate signature differs")
	}
	base := []string{"--repositories-file", filepath.Join(cache, "repositories"), "--cache-dir", cache, "--cache-max-age", "60", "--wait", "5", "--timeout", "15", "--no-network"}
	// fix accepts package names, not exact atoms, and keeps world unchanged.
	// The original immutable indexes and two complete simulations bind each
	// reinstall to the exact originally signed Expected version. No upgrade,
	// dependency addition or repair of an unrelated package is permitted.
	for i := 0; i < 2; i++ {
		output, err := runSecurityPackageCommand(ctx, "registered-plan", append(append(append([]string(nil), base...), "--simulate", "fix", "--reinstall"), names...)...)
		if err != nil {
			return err
		}
		if err := securityRuntimeReinstallPlan(string(output), installed, receipt, names); err != nil {
			return err
		}
	}
	if err := authorize(ctx); err != nil {
		return err
	}
	if err := verifySecurityPackageConstraints(constraints); err != nil {
		return err
	}
	if _, err := verifySecurityRuntimeCache(ctx, receipt); err != nil {
		return err
	}
	loader, err := hashSecurityMuslLoader(ctx)
	if err != nil || loader != loaderBefore {
		return fmt.Errorf("musl original replay loader changed before dispatch")
	}
	current, err := runSecurityPackageCommand(ctx, "registered-inventory", "info", "-v")
	if err != nil {
		return err
	}
	packages, err := securityInstalledPackages(string(current))
	if err != nil || !reflect.DeepEqual(packages, installed) {
		return fmt.Errorf("musl original replay inventory changed before dispatch")
	}
	if err := authorize(ctx); err != nil {
		return err
	}
	if err := verifySecurityPackageConstraints(constraints); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := install(ctx, append(append(append([]string(nil), base...), "fix", "--reinstall"), names...)); err != nil {
		return err
	}
	current, err = runSecurityPackageCommand(ctx, "registered-inventory", "info", "-v")
	if err != nil {
		return err
	}
	packages, err = securityInstalledPackages(string(current))
	if err != nil || !reflect.DeepEqual(packages, installed) {
		return fmt.Errorf("musl original replay changed installed versions")
	}
	want := loaderBefore
	for _, name := range names {
		if name == "musl" {
			want = receipt.LoaderExpected
		}
	}
	loader, err = hashSecurityMuslLoader(ctx)
	if err != nil || loader != want {
		return fmt.Errorf("musl original registered payload repair not confirmed")
	}
	if err := verifySecurityPackageConstraints(constraints); err != nil {
		return err
	}
	_, err = verifySecurityRuntimeCache(ctx, receipt)
	return err
}

func repairEmptyRuntimeSecurityPackages(ctx context.Context, permit *CompatPermit) error {
	if !validCompatPermit(permit) || len(permit.Guests) != 0 || !securityRuntimeHash.MatchString(permit.HostIdentity) {
		return fmt.Errorf("musl runtime maintenance waits for empty host authority")
	}
	return repairSecurityPackageTransaction(ctx, securityLxcfsTargets, func(ctx context.Context) error {
		return authorizeEmptySecurityHost(ctx, permit)
	}, permit.HostIdentity)
}
