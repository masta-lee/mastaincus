//go:build linux

package provisioning

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"
)

// Signed same-branch leaf packages only. Kernel, Incus, storage and service
// restarts stay under their separately validated maintenance recipes.
var securityLeaves = []string{"openssl", "libssl3", "libcrypto3", "curl", "libcurl", "ca-certificates",
	"lxc", "lxc-libs", "sqlite-libs", "libseccomp", "libcap2", "acl-libs", "libattr", "libuv", "lz4-libs", "zstd-libs", "xz-libs", "libintl", "libgcc",
	"tar", "gzip", "xz", "squashfs-tools", "rsync", "rsync-openrc", "libpsl", "libidn2", "libunistring", "c-ares", "brotli-libs", "nghttp2-libs"}
var securityPackageVersionChange = regexp.MustCompile(`(?m)Upgrading ([a-zA-Z0-9+_.-]+) \(([0-9][a-zA-Z0-9+_.~-]*) -> ([0-9][a-zA-Z0-9+_.~-]*)\)`)
var securityPackageInstallation = regexp.MustCompile(`(?m)Installing ([a-zA-Z0-9+_.-]+) \(([0-9][a-zA-Z0-9+_.~-]*)\)`)
var installedSecurityPackage = regexp.MustCompile(`^([a-zA-Z0-9+_.-]+)-([0-9][a-zA-Z0-9+_.~-]*)$`)
var securityMajorVersion = regexp.MustCompile(`^([0-9]+)(?:\.|-r)`)
var securityCertificateVersion = regexp.MustCompile(`^[0-9]{8}-r[0-9]+$`)

type securityPackageCommandError struct {
	stage, outcome, diagnostic string
	cause                      error
}

func (e *securityPackageCommandError) Error() string {
	return fmt.Sprintf("security package command failed (stage=%s, outcome=%s, diagnostic=%s)", e.stage, e.outcome, e.diagnostic)
}
func (e *securityPackageCommandError) Unwrap() error { return e.cause }

func securityPackageCommandFailure(stage string, output []byte, cause error) error {
	if cause == nil {
		return nil
	}
	// The diagnostic names are fixed. Private mirrors, tokens, argv and raw
	// tool output never become the error text sent to the controller or CI.
	switch stage {
	case "installed-inventory", "signed-index-update", "first-plan", "candidate-fetch", "candidate-verify", "original-cache-fetch", "version-order",
		"pre-install-inventory", "repeat-plan", "latest-inventory", "final-inventory", "confirm-inventory", "registered-plan", "registered-inventory", "install":
	default:
		stage = "unknown"
	}
	outcome := "rejected"
	var exit *exec.ExitError
	switch {
	case errors.Is(cause, context.DeadlineExceeded):
		outcome = "deadline"
	case errors.Is(cause, context.Canceled):
		outcome = "cancelled"
	case errors.As(cause, &exit):
		outcome = fmt.Sprintf("exit-%d", exit.ExitCode())
	}
	text, diagnostic := strings.ToLower(string(output)), "unknown"
	switch {
	case strings.Contains(text, "unrecognized option"), strings.Contains(text, "unknown option"), strings.Contains(text, "invalid option"), strings.Contains(text, "not an apk command"):
		diagnostic = "unsupported-option"
	case strings.Contains(text, "untrusted"), strings.Contains(text, "bad signature"), strings.Contains(text, "bad archive"), strings.Contains(text, "bad checksum"):
		diagnostic = "signature-or-content"
	case strings.Contains(text, "unable to select package"), strings.Contains(text, "breaks: world"), strings.Contains(text, "conflicts:"):
		diagnostic = "package-constraints"
	case strings.Contains(text, "temporary error"), strings.Contains(text, "network unreachable"), strings.Contains(text, "dns lookup error"), strings.Contains(text, "connection timed out"):
		diagnostic = "network"
	}
	return &securityPackageCommandError{stage: stage, outcome: outcome, diagnostic: diagnostic, cause: cause}
}

func runSecurityPackageCommand(ctx context.Context, stage string, args ...string) ([]byte, error) {
	output, err := run(ctx, "apk", args...)
	return output, securityPackageCommandFailure(stage, output, err)
}

func securitySameSeries(name, old, next string) bool {
	if name == "musl" || name == "musl-utils" {
		return securityMuslVersion.MatchString(old) && securityMuslVersion.MatchString(next)
	}
	// ca-certificates is a signed dated trust-store revision, not a program
	// major. Ordering is still checked by apk before any mutation.
	if name == "ca-certificates" {
		return securityCertificateVersion.MatchString(old) && securityCertificateVersion.MatchString(next)
	}
	a, b := securityMajorVersion.FindStringSubmatch(old), securityMajorVersion.FindStringSubmatch(next)
	return a != nil && b != nil && a[1] == b[1]
}

func securityInstalledPackages(output string) (map[string]string, error) {
	packages := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line == "" {
			continue
		}
		match := installedSecurityPackage.FindStringSubmatch(line)
		if match == nil || packages[match[1]] != "" || len(packages) >= 8192 {
			return nil, fmt.Errorf("security package inventory invalid")
		}
		packages[match[1]] = match[2]
	}
	return packages, nil
}
func securityExpectedPackages(before map[string]string, plan string) map[string]string {
	expected := map[string]string{}
	for name, version := range before {
		expected[name] = version
	}
	for _, change := range securityPackageVersionChange.FindAllStringSubmatch(plan, -1) {
		expected[change[1]] = change[3]
	}
	for _, addition := range securityPackageInstallation.FindAllStringSubmatch(plan, -1) {
		expected[addition[1]] = addition[2]
	}
	return expected
}

// Alpine 3.24 split _dbm out of the interpreter, then rebuilt that module
// separately as python3-extra r3 using gdbm. Interpreter/cache revisions remain
// r2. Bind only these reviewed combinations in the complete signed plan;
// unrelated dependency additions and administrator world changes stay refused.
var securityPythonGroup = []string{"python3", "python3-ndbm", "pyc", "python3-pyc", "python3-pycache-pyc0"}

func reviewedSecurityPython(version string) bool {
	return version == "3.14.8-r0" || version == "3.14.10-r1" || version == "3.14.10-r2"
}
func securityPythonSplit(before map[string]string, name, version string) bool {
	return name == "python3-ndbm" && reviewedSecurityNdbm(version) && before["python3"] == "3.14.10-r2" && before[name] == ""
}
func reviewedSecurityNdbm(version string) bool {
	return version == "3.14.10-r2" || version == "3.14.10-r3"
}

func safeSecurityPackagePlan(output string, before map[string]string) error {
	return safeSecurityPackagePlanFor(output, before, securityLeaves)
}
func safeSecurityPackagePlanFor(output string, before map[string]string, targets []string) error {
	if strings.Contains(output, "Removing ") || strings.Contains(output, "Downgrading ") || strings.Contains(output, "UNTRUSTED") {
		return fmt.Errorf("security package plan refused")
	}
	if strings.Contains(output, "Reinstalling ") {
		return fmt.Errorf("unexpected security package installation refused")
	}
	expected := securityExpectedPackages(before, output)
	if err := securityMuslPlan(before, expected, targets); err != nil {
		return err
	}
	pythonAligned := reviewedSecurityPython(before["python3"]) && expected["python3"] == "3.14.10-r2"
	if pythonAligned {
		for _, name := range securityPythonGroup {
			if name == "python3-ndbm" {
				if before[name] != "" && !reviewedSecurityNdbm(before[name]) || expected[name] != "" && !reviewedSecurityNdbm(expected[name]) {
					return fmt.Errorf("Python split companion not reviewed")
				}
				continue
			}
			if before[name] != "" && (before[name] != before["python3"] || expected[name] != expected["python3"]) {
				return fmt.Errorf("Python split group not aligned")
			}
		}
		if expected["python3-ndbm"] == "3.14.10-r3" && expected["gdbm"] != "1.26-r0" {
			return fmt.Errorf("Python split gdbm dependency not aligned")
		}
	}
	additions := securityPackageInstallation.FindAllStringSubmatch(output, -1)
	if strings.Count(output, "Installing ") != len(additions) || len(additions) > 2 {
		return fmt.Errorf("unexpected security package installation refused")
	}
	additionNames := map[string]bool{}
	for _, addition := range additions {
		companion := addition[1] == "python3-ndbm" && reviewedSecurityNdbm(addition[2])
		gdbm := addition[1] == "gdbm" && addition[2] == "1.26-r0" && expected["python3-ndbm"] == "3.14.10-r3"
		if !pythonAligned || (!companion && !gdbm) || before[addition[1]] != "" || additionNames[addition[1]] {
			return fmt.Errorf("unexpected security package installation refused")
		}
		additionNames[addition[1]] = true
	}
	allowed := map[string]bool{}
	seen := map[string]bool{}
	for _, name := range targets {
		allowed[name] = true
	}
	for _, change := range securityPackageVersionChange.FindAllStringSubmatch(output, -1) {
		old, ok := before[change[1]]
		python := false
		for _, name := range securityPythonGroup {
			if name == change[1] {
				python = pythonAligned && old == before["python3"] && change[3] == "3.14.10-r2"
				if name == "python3-ndbm" {
					python = pythonAligned && old == "3.14.10-r2" && change[3] == "3.14.10-r3"
				}
			}
		}
		if !ok || (!allowed[change[1]] && !python) || seen[change[1]] || old != change[2] || !securitySameSeries(change[1], old, change[3]) {
			return fmt.Errorf("unreviewed security package change refused")
		}
		seen[change[1]] = true
	}
	if strings.Count(output, "Upgrading ") != len(securityPackageVersionChange.FindAllStringSubmatch(output, -1)) {
		return fmt.Errorf("unknown security package plan format")
	}
	return nil
}
func repairSecurityPackages(ctx context.Context) error {
	return repairSecurityPackageSet(ctx, securityLeaves, nil)
}
func repairSecurityPackageSet(ctx context.Context, targets []string, authorize func(context.Context) error) error {
	return repairSecurityPackageTransaction(ctx, targets, authorize, "")
}
func repairSecurityPackageTransaction(ctx context.Context, targets []string, authorize func(context.Context) error, runtimeAuthority string) error {
	return repairSecurityPackageTransactionWithInstaller(ctx, targets, authorize, runtimeAuthority, func(ctx context.Context, args []string) error {
		_, err := runSecurityPackageCommand(ctx, "install", args...)
		return err
	})
}

func repairSecurityPackageTransactionWithInstaller(ctx context.Context, targets []string, authorize func(context.Context) error, runtimeAuthority string, install func(context.Context, []string) error) error {
	if install == nil {
		return fmt.Errorf("security package installer unavailable")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("security package update requires root")
	}
	if securityMuslTargets(targets) && (authorize == nil || !securityRuntimeHash.MatchString(runtimeAuthority)) {
		return fmt.Errorf("musl runtime update requires separate empty-host authority")
	}
	release, _, err := readLegacyWorldFile("/etc/alpine-release", false)
	if err != nil {
		return fmt.Errorf("security package distribution needs reviewed update")
	}
	repositories, _, err := readLegacyWorldFile("/etc/apk/repositories", false)
	if err != nil {
		return err
	}
	reviewedRepositories, err := reviewedSecurityRepositories(string(release), string(repositories))
	if err != nil {
		return err
	}
	unlock, err := lock()
	if err != nil {
		return err
	}
	defer unlock()
	if authorize != nil {
		if err := authorize(ctx); err != nil {
			return err
		}
	}
	installed, err := runSecurityPackageCommand(ctx, "installed-inventory", "info", "-v")
	if err != nil {
		return err
	}
	before, err := securityInstalledPackages(string(installed))
	if err != nil {
		return err
	}
	constraints, err := readSecurityPackageConstraints("/etc/alpine-release", "/etc/apk/repositories", "/etc/apk/world")
	if err != nil {
		return err
	}
	if string(constraints[0].Data) != string(release) || string(constraints[1].Data) != string(repositories) {
		return fmt.Errorf("security package administrator configuration changed")
	}
	var saved *securityRuntimeReceipt
	var environment securityRuntimeEnvironment
	loaderBefore := ""
	if runtimeAuthority != "" {
		environment, err = securityRuntimeSnapshot(runtimeAuthority, targets, constraints)
		if err != nil {
			return err
		}
		loaderBefore, err = hashSecurityMuslLoader(ctx)
		if err != nil {
			return err
		}
		saved, err = readSecurityRuntimeReceipt(securityRuntimeReceiptPath)
		if err != nil {
			return err
		}
		reuse, err := securityRuntimeReceiptState(saved, environment, before, loaderBefore, time.Now())
		if err != nil {
			return err
		}
		if reuse {
			return nil
		}
		if saved != nil && saved.Phase == "prepared" {
			// An installed database entry does not prove all of that package's
			// files survived a power loss. Repair only already registered original
			// Expected packages before completing the remaining original upgrade.
			if err := repairSecurityRuntimeRegisteredFiles(ctx, saved, environment, before, loaderBefore, constraints, authorize, install); err != nil {
				return err
			}
			loaderBefore, err = hashSecurityMuslLoader(ctx)
			if err != nil {
				return err
			}
		}
		if saved != nil && saved.Phase == "prepared" && reflect.DeepEqual(before, saved.Expected) {
			if err := authorize(ctx); err != nil {
				return err
			}
			cache, err := verifySecurityRuntimeCache(ctx, saved)
			if err != nil {
				return err
			}
			candidate, err := verifyCachedSecurityMuslLoader(ctx, cache, saved.Expected["musl"])
			if err != nil || candidate != saved.LoaderExpected {
				return fmt.Errorf("musl original completion candidate changed")
			}
			if err := authorize(ctx); err != nil {
				return err
			}
			if err := confirmSecurityRuntimeReceipt(ctx, *saved, environment, before, constraints); err != nil {
				return err
			}
			// The original registered payloads and final complete installation
			// are now confirmed. Retire only the authenticated retained cache.
			_ = os.RemoveAll(cache)
			return nil
		}
	}
	validatePlan := func(output string) error {
		if saved != nil && saved.Phase == "prepared" {
			return securityRuntimeResumePlan(output, before, saved)
		}
		return safeSecurityPackagePlanFor(output, before, targets)
	}
	requested := []string{}
	for _, name := range targets {
		if before[name] != "" {
			requested = append(requested, name)
		}
	}
	if strings.HasPrefix(strings.TrimSpace(string(release)), "3.24.") && reviewedSecurityPython(before["python3"]) {
		for _, name := range securityPythonGroup {
			if before[name] != "" {
				requested = append(requested, name)
			}
		}
	}
	if len(requested) == 0 {
		return nil
	}
	// A prepared musl transaction retains its original signed indexes and all
	// package artifacts. It must not resolve a different upstream revision when
	// retrying a partly installed original plan.
	cache, keepCache := "", false
	resuming := saved != nil && saved.Phase == "prepared"
	if resuming {
		cache, err = verifySecurityRuntimeCache(ctx, saved)
		keepCache = true
	} else {
		cache, err = os.MkdirTemp("/var/lib/incudal-agent", ".security-packages-*")
	}
	if err != nil {
		return err
	}
	defer func() {
		if !keepCache {
			_ = os.RemoveAll(cache)
		}
	}()
	if filepath.Dir(cache) != "/var/lib/incudal-agent" {
		return fmt.Errorf("security package cache invalid")
	}
	repositoryPath := filepath.Join(cache, "repositories")
	if !resuming {
		if err = os.WriteFile(repositoryPath, []byte(reviewedRepositories), 0600); err != nil {
			return err
		}
	}
	base := []string{"--repositories-file", repositoryPath, "--cache-dir", cache, "--cache-max-age", "60", "--wait", "5", "--timeout", "15"}
	// apk --simulate intentionally never writes missing indexes, even with
	// --update-cache. Fetch and verify them explicitly once before simulation.
	if resuming {
		base = append(base, "--no-network")
	} else {
		if _, err = runSecurityPackageCommand(ctx, "signed-index-update", append(append([]string{}, base...), "update")...); err != nil {
			return err
		}
	}
	output, err := runSecurityPackageCommand(ctx, "first-plan", append(append([]string{}, base...), append([]string{"--simulate", "upgrade"}, requested...)...)...)
	if err != nil {
		return err
	}
	if err = validatePlan(string(output)); err != nil {
		return err
	}
	expected := securityExpectedPackages(before, string(output))
	var transaction *securityRuntimeReceipt
	if runtimeAuthority != "" {
		if saved != nil && saved.Phase == "prepared" {
			transaction = saved
		} else {
			loaderExpected, err := fetchSecurityMuslLoader(ctx, base, cache, expected["musl"])
			if err != nil {
				return err
			}
			if expected["musl"] == before["musl"] && loaderExpected != loaderBefore {
				return fmt.Errorf("musl installed loader differs from the signed package")
			}
			transaction = &securityRuntimeReceipt{Version: 1, Recipe: securityRuntimeRecipe, Phase: "prepared", CheckedAt: time.Now().UTC().Format(time.RFC3339Nano), Environment: environment, Before: before, Expected: expected, Plan: string(output), LoaderBefore: loaderBefore, LoaderExpected: loaderExpected}
		}
	}
	pinned := []string{}
	for _, change := range securityPackageVersionChange.FindAllStringSubmatch(string(output), -1) {
		order, err := runSecurityPackageCommand(ctx, "version-order", "version", "--test", change[2], change[3])
		if err != nil || strings.TrimSpace(string(order)) != "<" {
			return fmt.Errorf("security package version order refused")
		}
		pinned = append(pinned, change[1])
	}
	if len(securityPackageInstallation.FindAllStringSubmatch(string(output), -1)) > 0 {
		// upgrade the already installed world atom; add would persist a new
		// administrator constraint. The repeated complete plan binds the
		// companion version and rejects extra dependencies before mutation.
		if before["python3"] == "3.14.10-r2" {
			pinned = append(pinned, "python3")
		}
		if before["python3-ndbm"] != "" {
			pinned = append(pinned, "python3-ndbm")
		}
	}
	if len(pinned) == 0 {
		if transaction != nil {
			if err := authorize(ctx); err != nil {
				return err
			}
			err := confirmSecurityRuntimeReceipt(ctx, *transaction, environment, before, constraints)
			if err == nil {
				keepCache = false
			}
			return err
		}
		return nil
	}
	if transaction != nil && !resuming {
		if err := cacheSecurityRuntimePlan(ctx, base, before, expected); err != nil {
			return err
		}
		transaction.CacheID = filepath.Base(cache)
		transaction.CacheFiles, err = securityRuntimeCacheSnapshot(ctx, cache)
		if err != nil {
			return err
		}
		base = append(base, "--no-network")
	}
	// Exact add atoms would persist in /etc/apk/world and block the next patch.
	// upgrade accepts package names. The same verified cached index and complete
	// second plan bind their exact versions without modifying world constraints.
	// Package names still let apk solve dependencies. Re-simulate the upgrade
	// transaction and require the original complete installed baseline before
	// mutation; no extra dependency or unrelated package change is authorized.
	current, err := runSecurityPackageCommand(ctx, "pre-install-inventory", "info", "-v")
	if err != nil {
		return err
	}
	currentPackages, err := securityInstalledPackages(string(current))
	if err != nil || !reflect.DeepEqual(currentPackages, before) {
		return fmt.Errorf("security package baseline changed")
	}
	actualPlan, err := runSecurityPackageCommand(ctx, "repeat-plan", append(append([]string{}, base...), append([]string{"--simulate", "upgrade"}, pinned...)...)...)
	if err != nil {
		return err
	}
	if err = validatePlan(string(actualPlan)); err != nil {
		return err
	}
	if !reflect.DeepEqual(expected, securityExpectedPackages(before, string(actualPlan))) {
		return fmt.Errorf("security package install plan changed")
	}
	if authorize != nil {
		if err := authorize(ctx); err != nil {
			return err
		}
	}
	// World and its original permissions must still match after authorization,
	// before APK can install anything. Detecting this only after installation is
	// too late to protect a concurrent administrator's constraints.
	if err := verifySecurityPackageConstraints(constraints); err != nil {
		return err
	}
	if transaction != nil {
		if _, err := verifySecurityRuntimeCache(ctx, transaction); err != nil {
			return err
		}
		loader, err := hashSecurityMuslLoader(ctx)
		if err != nil || loader != loaderBefore {
			return fmt.Errorf("musl loader changed before original package installation")
		}
		if err := saveSecurityRuntimeReceipt(securityRuntimeReceiptPath, *transaction); err != nil {
			return err
		}
		keepCache = true
		if err := verifySecurityPackageConstraints(constraints); err != nil {
			return err
		}
	}
	// Authorization and receipt publication can take time. Recheck the actual
	// complete database one final time before the installer obtains APK's lock.
	latest, err := runSecurityPackageCommand(ctx, "latest-inventory", "info", "-v")
	if err != nil {
		return err
	}
	latestPackages, err := securityInstalledPackages(string(latest))
	if err != nil || !reflect.DeepEqual(latestPackages, before) {
		return fmt.Errorf("security package baseline changed before installation")
	}
	if err := verifySecurityPackageConstraints(constraints); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err = install(ctx, append(append([]string{}, base...), append([]string{"upgrade"}, pinned...)...)); err != nil {
		return err
	}
	after, err := runSecurityPackageCommand(ctx, "final-inventory", "info", "-v")
	if err != nil {
		return err
	}
	afterPackages, err := securityInstalledPackages(string(after))
	if err != nil || !reflect.DeepEqual(expected, afterPackages) {
		return fmt.Errorf("security package installation not confirmed")
	}
	if err := verifySecurityPackageConstraints(constraints); err != nil {
		return err
	}
	if transaction != nil {
		err := confirmSecurityRuntimeReceipt(ctx, *transaction, environment, afterPackages, constraints)
		if err == nil {
			keepCache = false
		}
		return err
	}
	return nil
}
