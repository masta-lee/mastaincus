//go:build linux

package provisioning

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestMuslOnlyUsesCompleteEmptyHostRuntimePlan(t *testing.T) {
	before := map[string]string{"musl": "1.2.5-r20", "musl-utils": "1.2.5-r20", "linux-virt": "6.12.1-r0", "incus": "6.0.0-r0"}
	plan := "Upgrading musl (1.2.5-r20 -> 1.2.6-r2)\nUpgrading musl-utils (1.2.5-r20 -> 1.2.6-r2)"
	if safeSecurityPackagePlan(plan, before) == nil {
		t.Fatal("live-host leaf updater admitted libc replacement")
	}
	if err := safeSecurityPackagePlanFor(plan, before, securityLxcfsTargets); err != nil {
		t.Fatal("complete reviewed empty-host runtime update refused", err)
	}
	for _, bad := range []string{
		strings.Split(plan, "\n")[0],
		strings.Split(plan, "\n")[1],
		strings.ReplaceAll(plan, "1.2.6-r2", "1.3.0-r0"),
		strings.ReplaceAll(plan, "1.2.6-r2", "2.2.6-r2"),
		strings.ReplaceAll(plan, "1.2.6-r2", "1.2.06-r2"),
		strings.ReplaceAll(plan, "1.2.6-r2", "1.2.6_rc1-r2"),
		plan + "\nInstalling musl-dev (1.2.6-r2)",
		plan + "\nUpgrading linux-virt (6.12.1-r0 -> 6.12.2-r0)",
		plan + "\nUpgrading incus (6.0.0-r0 -> 6.0.1-r0)",
	} {
		if safeSecurityPackagePlanFor(bad, before, securityLxcfsTargets) == nil {
			t.Fatal("partial, expanded or unreviewed runtime change admitted", bad)
		}
	}
	if safeSecurityPackagePlanFor(plan, before, []string{"musl"}) == nil {
		t.Fatal("partial runtime capability admitted")
	}
	mixed := map[string]string{"musl": "1.2.6-r1", "musl-utils": "1.2.5-r20"}
	if safeSecurityPackagePlanFor("Upgrading musl-utils (1.2.5-r20 -> 1.2.6-r1)", mixed, securityLxcfsTargets) == nil {
		t.Fatal("unrecorded mixed runtime group accepted")
	}
	if err := repairSecurityPackageSet(context.Background(), securityLxcfsTargets, func(context.Context) error { t.Fatal("authority-less transaction ran"); return nil }); err == nil {
		t.Fatal("empty-host target list became installation authority")
	}
}

func TestSecurityPackageCommandDiagnosticsRetainCauseWithoutPrivateOutput(t *testing.T) {
	cause := errors.New("private source https://mirror.invalid/token=not-for-logs")
	for _, test := range []struct{ output, diagnostic string }{
		{"unrecognized option --private-token=secret", "unsupported-option"},
		{"ERROR: UNTRUSTED https://mirror.invalid/token=secret", "signature-or-content"},
		{"unable to select packages: private-host", "package-constraints"},
		{"musl=1.2.6-r3: unable to select package (or its dependencies): private-host", "package-constraints"},
		{"temporary error: private-dns-name", "network"},
		{"sensitive unexpected output", "unknown"},
	} {
		err := securityPackageCommandFailure("candidate-fetch", []byte(test.output), cause)
		if !errors.Is(err, cause) || err.Error() != "security package command failed (stage=candidate-fetch, outcome=rejected, diagnostic="+test.diagnostic+")" {
			t.Fatal("fixed command diagnostic lost its cause or exposed private bytes")
		}
	}
	for _, test := range []struct {
		cause   error
		outcome string
	}{{context.Canceled, "cancelled"}, {context.DeadlineExceeded, "deadline"}} {
		err := securityPackageCommandFailure("private-untrusted-stage", nil, test.cause)
		if !errors.Is(err, test.cause) || err.Error() != "security package command failed (stage=unknown, outcome="+test.outcome+", diagnostic=unknown)" {
			t.Fatal("unknown stage or context failure produced unsafe diagnostics")
		}
	}
	if securityPackageCommandFailure("candidate-fetch", []byte("UNTRUSTED"), nil) != nil {
		t.Fatal("successful command acquired a fabricated failure")
	}
}

func muslReceiptFixture() securityRuntimeReceipt {
	before := map[string]string{"musl": "1.2.5-r20", "musl-utils": "1.2.5-r20", "curl": "8.17.0-r0", "linux-virt": "6.12.1-r0"}
	plan := "Upgrading musl (1.2.5-r20 -> 1.2.6-r2)\nUpgrading musl-utils (1.2.5-r20 -> 1.2.6-r2)\nUpgrading curl (8.17.0-r0 -> 8.17.0-r1)"
	environment := securityRuntimeEnvironment{HostIdentity: strings.Repeat("a", 64), Architecture: runtime.GOARCH, BootID: "11111111-1111-4111-8111-111111111111", Files: map[string]string{}, Modes: map[string]uint32{}, Targets: append([]string(nil), securityLxcfsTargets...)}
	for _, path := range []string{"/etc/alpine-release", "/etc/apk/repositories", "/etc/apk/world"} {
		environment.Files[path] = legacyWorldHash(path)
		environment.Modes[path] = 0644
	}
	return securityRuntimeReceipt{Version: 1, Recipe: securityRuntimeRecipe, Phase: "prepared", CheckedAt: time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), Environment: environment, Before: before, Expected: securityExpectedPackages(before, plan), Plan: plan, LoaderBefore: strings.Repeat("b", 64), LoaderExpected: strings.Repeat("c", 64), CacheID: ".security-packages-12345678", CacheFiles: map[string]string{"repositories": strings.Repeat("d", 64), "APKINDEX.original.tar.gz": strings.Repeat("e", 64)}}
}

func TestMuslInterruptedTransactionOnlyResumesOriginalSignedExpectedSet(t *testing.T) {
	receipt := muslReceiptFixture()
	partial := map[string]string{"musl": receipt.Expected["musl"], "musl-utils": receipt.Before["musl-utils"], "curl": receipt.Before["curl"], "linux-virt": receipt.Before["linux-virt"]}
	plan := "Upgrading musl-utils (1.2.5-r20 -> 1.2.6-r2)\nUpgrading curl (8.17.0-r0 -> 8.17.0-r1)"
	if err := securityRuntimeResumePlan(plan, partial, &receipt); err != nil {
		t.Fatal("original partly installed transaction cannot complete", err)
	}
	if _, err := securityRuntimeReceiptState(&receipt, receipt.Environment, partial, receipt.LoaderExpected, time.Now()); err != nil {
		t.Fatal("signed original candidate loader rejected after partial installation", err)
	}
	for _, bad := range []string{strings.Split(plan, "\n")[0], strings.ReplaceAll(plan, "1.2.6-r2", "1.2.6-r3"), plan + "\nInstalling unknown (1-r0)", plan + "\nUpgrading linux-virt (6.12.1-r0 -> 6.12.2-r0)", plan + "\nRemoving curl", plan + "\n" + plan, "Upgrading musl-utils (unknown)", "UNTRUSTED"} {
		if securityRuntimeResumePlan(bad, partial, &receipt) == nil {
			t.Fatal("recovery enlarged or changed original authorization", bad)
		}
	}
	for _, drift := range []string{"missing", "extra", "different", "loader"} {
		current := map[string]string{}
		for name, version := range partial {
			current[name] = version
		}
		loader := receipt.LoaderExpected
		switch drift {
		case "missing":
			delete(current, "linux-virt")
		case "extra":
			current["unexpected"] = "1-r0"
		case "different":
			current["curl"] = "8.17.1-r0"
		case "loader":
			loader = strings.Repeat("f", 64)
		}
		if _, err := securityRuntimeReceiptState(&receipt, receipt.Environment, current, loader, time.Now()); err == nil {
			t.Fatal("unrecorded installation or loader drift admitted", drift)
		}
	}
	if err := securityRuntimeResumePlan("", receipt.Expected, &receipt); err != nil {
		t.Fatal("lost completion reply could not be verified", err)
	}
}

func TestMuslPreparedResumesEitherOriginalFileDatabaseCommitOrder(t *testing.T) {
	receipt := muslReceiptFixture()
	partial := securityExpectedPackages(receipt.Before, "Upgrading musl (1.2.5-r20 -> 1.2.6-r2)")
	for _, inventory := range []map[string]string{receipt.Before, partial, receipt.Expected} {
		for _, loader := range []string{receipt.LoaderBefore, receipt.LoaderExpected} {
			if reuse, err := securityRuntimeReceiptState(&receipt, receipt.Environment, inventory, loader, time.Now()); err != nil || reuse {
				t.Fatal("original signed file/database commit order cannot resume", inventory["musl"], loader, reuse, err)
			}
		}
		if _, err := securityRuntimeReceiptState(&receipt, receipt.Environment, inventory, strings.Repeat("f", 64), time.Now()); err == nil {
			t.Fatal("third loader hash admitted as an installation interruption")
		}
	}
	changed, _ := json.Marshal(receipt.Environment)
	var environment securityRuntimeEnvironment
	_ = json.Unmarshal(changed, &environment)
	environment.Files["/etc/apk/world"] = strings.Repeat("f", 64)
	if _, err := securityRuntimeReceiptState(&receipt, environment, receipt.Before, receipt.LoaderExpected, time.Now()); err == nil {
		t.Fatal("prepared replay adopted a later administrator world")
	}
}

func TestMuslRegisteredPayloadReplayOnlyReinstallsExactOriginalChangedPackages(t *testing.T) {
	receipt := muslReceiptFixture()
	partial := securityExpectedPackages(receipt.Before, "Upgrading musl (1.2.5-r20 -> 1.2.6-r2)")
	names, err := securityRuntimeReinstallPackages(&receipt, partial)
	if err != nil || !reflect.DeepEqual(names, []string{"musl"}) {
		t.Fatal("registered partial replay did not select the exact original core", names, err)
	}
	if err := securityRuntimeReinstallPlan("(1/1) Reinstalling musl (1.2.6-r2)\nOK: 1 MiB in 4 packages", partial, &receipt, names); err != nil {
		t.Fatal("exact original core reinstallation refused", err)
	}
	names, err = securityRuntimeReinstallPackages(&receipt, receipt.Expected)
	if err != nil || !reflect.DeepEqual(names, []string{"curl", "musl", "musl-utils"}) {
		t.Fatal("database completion skipped potentially unfinished original payloads", names, err)
	}
	plan := "(1/3) Reinstalling musl (1.2.6-r2)\n(2/3) Reinstalling musl-utils (1.2.6-r2)\n(3/3) Reinstalling curl (8.17.0-r1)"
	if err := securityRuntimeReinstallPlan(plan, receipt.Expected, &receipt, names); err != nil {
		t.Fatal("complete exact original registered payload repair refused", err)
	}
	for _, bad := range []string{strings.Split(plan, "\n")[0], plan + "\n" + strings.Split(plan, "\n")[0], strings.ReplaceAll(plan, "1.2.6-r2", "1.2.6-r3"), strings.Replace(plan, "Reinstalling musl ", "[APK unavailable, skipped] Reinstalling musl ", 1), plan + "\nReinstalling linux-virt (6.12.1-r0)", plan + "\nInstalling unexpected (1-r0)", plan + "\nUpgrading curl (8.17.0-r1 -> 8.17.0-r2)", plan + "\nPurging linux-virt (6.12.1-r0)", plan + "\nReplacing musl (1.2.6-r2 -> 1.2.6-r2)", "UNTRUSTED\n" + plan} {
		if securityRuntimeReinstallPlan(bad, receipt.Expected, &receipt, names) == nil {
			t.Fatal("original replay expanded, skipped or changed a registered package", bad)
		}
	}
	if securityRuntimeReinstallPlan(plan, receipt.Expected, &receipt, append(names, "linux-virt")) == nil {
		t.Fatal("caller extended the original repair package names")
	}
	if names, err := securityRuntimeReinstallPackages(&receipt, receipt.Before); err != nil || len(names) != 0 {
		t.Fatal("unregistered original upgrades were turned into reinstalls", names, err)
	}
	receipt.Phase = "installed"
	if _, err := securityRuntimeReinstallPackages(&receipt, receipt.Expected); err == nil {
		t.Fatal("installed receipt admitted repeated payload repair")
	}
}

func TestMuslInstalledReceiptDoesNotClaimActivationOrReblessChanges(t *testing.T) {
	receipt := muslReceiptFixture()
	receipt.Phase = "installed"
	now := time.Now()
	if reuse, err := securityRuntimeReceiptState(&receipt, receipt.Environment, receipt.Expected, receipt.LoaderExpected, now); err != nil || !reuse {
		t.Fatal("verified current installed transaction not reusable", reuse, err)
	}
	for _, drift := range []string{"boot", "age", "inventory"} {
		env := receipt.Environment
		packages := map[string]string{}
		for name, version := range receipt.Expected {
			packages[name] = version
		}
		checkAt := now
		if drift == "boot" {
			env.BootID = "22222222-2222-4222-8222-222222222222"
		} else if drift == "age" {
			checkAt = now.Add(6 * time.Hour)
		} else {
			packages["curl"] = "8.17.0-r2"
		}
		if reuse, err := securityRuntimeReceiptState(&receipt, env, packages, receipt.LoaderExpected, checkAt); err != nil || reuse {
			t.Fatal("changed boot/old check/inventory skipped new signed checks", drift, reuse, err)
		}
	}
	for _, drift := range []string{"world", "repositories", "mode", "targets"} {
		data, _ := json.Marshal(receipt.Environment)
		var env securityRuntimeEnvironment
		_ = json.Unmarshal(data, &env)
		switch drift {
		case "world":
			env.Files["/etc/apk/world"] = strings.Repeat("e", 64)
		case "repositories":
			env.Files["/etc/apk/repositories"] = strings.Repeat("e", 64)
		case "mode":
			env.Modes["/etc/apk/world"] = 0600
		case "targets":
			env.Targets = append(env.Targets, "reviewed-new-tool")
		}
		if reuse, err := securityRuntimeReceiptState(&receipt, env, receipt.Expected, receipt.LoaderExpected, now); err != nil || reuse {
			t.Fatal("safe post-maintenance tool constraints became a permanent retry or a reused receipt", drift, reuse, err)
		}
	}
	for _, drift := range []string{"unsafe-mode", "identity", "architecture", "loader", "group"} {
		data, _ := json.Marshal(receipt.Environment)
		var env securityRuntimeEnvironment
		_ = json.Unmarshal(data, &env)
		packages := map[string]string{}
		for name, version := range receipt.Expected {
			packages[name] = version
		}
		loader := receipt.LoaderExpected
		switch drift {
		case "unsafe-mode":
			env.Modes["/etc/apk/world"] = 0666
		case "identity":
			env.HostIdentity = strings.Repeat("e", 64)
		case "architecture":
			env.Architecture = "unreviewed"
		case "loader":
			loader = strings.Repeat("e", 64)
		case "group":
			packages["musl-utils"] = "1.2.6-r3"
		}
		if reuse, err := securityRuntimeReceiptState(&receipt, env, packages, loader, now); err == nil || reuse {
			t.Fatal("installed receipt re-recorded a later external change", drift)
		}
	}
}

func TestMuslPrivateReceiptAndLastMomentWorldChange(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned persistent receipt and world publication")
	}
	directory, err := os.MkdirTemp("/root", "musl-receipt-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	path, world := filepath.Join(directory, "receipt.json"), filepath.Join(directory, "world")
	receipt := muslReceiptFixture()
	if err := saveSecurityRuntimeReceipt(path, receipt); err != nil {
		t.Fatal(err)
	}
	got, err := readSecurityRuntimeReceipt(path)
	if err != nil || !reflect.DeepEqual(*got, receipt) {
		t.Fatal("durable original plan not preserved", err)
	}
	data, _ := os.ReadFile(path)
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("runtime plan receipt is not private")
	}
	for _, bad := range []string{strings.TrimSuffix(string(data), "}") + `,"unknown":true}`, string(data) + "\n{}", strings.TrimSuffix(string(data), "}") + `,"version":1}`, strings.Replace(string(data), `"phase":"prepared"`, `"phase":"activated"`, 1), strings.Replace(string(data), receipt.CheckedAt, time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), 1)} {
		_ = os.WriteFile(path, []byte(bad), 0600)
		if _, err := readSecurityRuntimeReceipt(path); err == nil {
			t.Fatal("unknown/duplicate/future/activation receipt authorized a skip")
		}
	}
	_ = os.WriteFile(path, data, 0600)
	_ = os.Chmod(path, 0644)
	if _, err := readSecurityRuntimeReceipt(path); err == nil {
		t.Fatal("public receipt accepted")
	}
	_ = os.WriteFile(world, []byte("musl\ncurl\n"), 0644)
	constraints, err := readSecurityPackageConstraints(world)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifySecurityPackageConstraints(constraints); err != nil {
		t.Fatal("unchanged world rejected", err)
	}
	_ = os.WriteFile(world, []byte("musl=1.2.5-r20\ncurl\n"), 0644)
	if verifySecurityPackageConstraints(constraints) == nil {
		t.Fatal("last-moment administrator pin not detected before installation")
	}
	_ = os.WriteFile(world, constraints[0].Data, 0644)
	_ = os.Chmod(world, 0600)
	if verifySecurityPackageConstraints(constraints) == nil {
		t.Fatal("last-moment world permissions not detected")
	}
}

func TestMuslCompletedReceiptPreservesEvidenceBeforeNewConstraintPlan(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned completed installation evidence")
	}
	directory, err := os.MkdirTemp("/root", "musl-archive-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	path := filepath.Join(directory, "receipt.json")
	original := muslReceiptFixture()
	original.Phase = "installed"
	if err := saveSecurityRuntimeReceipt(path, original); err != nil {
		t.Fatal(err)
	}
	bytesBefore, _ := os.ReadFile(path)
	encoded, _ := json.Marshal(original)
	var next securityRuntimeReceipt
	_ = json.Unmarshal(encoded, &next)
	next.Environment.Files["/etc/apk/world"] = strings.Repeat("e", 64)
	next.Before = securityExpectedPackages(original.Expected, "")
	next.Expected = securityExpectedPackages(next.Before, "")
	next.Plan, next.CacheID, next.CacheFiles = "", "", nil
	next.LoaderBefore = original.LoaderExpected
	next.CheckedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := saveSecurityRuntimeReceipt(path, next); err != nil {
		t.Fatal("safe next signed constraint plan could not preserve original evidence", err)
	}
	archive := path + ".installed-" + legacyWorldHash(string(bytesBefore)) + ".json"
	archived, mode, err := readLegacyWorldFile(archive, true)
	if err != nil || mode != 0600 || !bytes.Equal(archived, bytesBefore) {
		t.Fatal("original completed receipt was changed or made public", err)
	}
	if err := saveSecurityRuntimeReceipt(path, next); err != nil {
		t.Fatal("identical current receipt created another generation", err)
	}
	files, _ := os.ReadDir(directory)
	if len(files) != 2 {
		t.Fatal("same completed receipt repeatedly archived", len(files))
	}
	current, _ := os.ReadFile(path)
	nextArchive := path + ".installed-" + legacyWorldHash(string(current)) + ".json"
	_ = os.WriteFile(nextArchive, []byte("foreign historical evidence"), 0600)
	third := next
	third.CheckedAt = time.Now().UTC().Add(time.Nanosecond).Format(time.RFC3339Nano)
	if err := saveSecurityRuntimeReceipt(path, third); err == nil {
		t.Fatal("changed archive was silently replaced")
	}
	unchanged, _ := os.ReadFile(path)
	if !bytes.Equal(current, unchanged) {
		t.Fatal("failed evidence archive overwrote the current installation receipt")
	}
}

func TestMuslOriginalCacheSurvivesAndRejectsChangedArtifacts(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("actual root-private original signed package cache")
	}
	base := "/var/lib/incudal-agent"
	_, beforeErr := os.Lstat(base)
	if err := os.MkdirAll(base, 0700); err != nil {
		t.Fatal(err)
	}
	if os.IsNotExist(beforeErr) {
		t.Cleanup(func() { _ = os.Remove(base) })
	}
	directory, err := os.MkdirTemp(base, ".security-packages-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	for name, data := range map[string]string{"repositories": "https://dl-cdn.alpinelinux.org/alpine/v3.24/main\n", "APKINDEX.original.tar.gz": strings.Repeat("original signed index fixture", 8), "musl-1.2.6-r2.01234567.apk": strings.Repeat("original signed package fixture", 8)} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	receipt := muslReceiptFixture()
	receipt.CacheID = filepath.Base(directory)
	receipt.CacheFiles, err = securityRuntimeCacheSnapshot(context.Background(), directory)
	if err != nil {
		t.Fatal(err)
	}
	if path, err := verifySecurityRuntimeCache(context.Background(), &receipt); err != nil || path != directory {
		t.Fatal("retained complete original cache not usable", path, err)
	}
	artifact := filepath.Join(directory, "musl-1.2.6-r2.01234567.apk")
	original, _ := os.ReadFile(artifact)
	for _, drift := range []string{"bytes", "mode", "missing", "extra", "link"} {
		_ = os.WriteFile(artifact, original, 0600)
		_ = os.Chmod(artifact, 0600)
		extra := filepath.Join(directory, "unexpected.apk")
		_ = os.Remove(extra)
		switch drift {
		case "bytes":
			_ = os.WriteFile(artifact, []byte("changed package content"), 0600)
		case "mode":
			_ = os.Chmod(artifact, 0644)
		case "missing":
			_ = os.Remove(artifact)
		case "extra":
			_ = os.WriteFile(extra, []byte("extra candidate"), 0600)
		case "link":
			_ = os.Remove(artifact)
			_ = os.Symlink(filepath.Join(directory, "repositories"), artifact)
		}
		if _, err := verifySecurityRuntimeCache(context.Background(), &receipt); err == nil {
			t.Fatal("modified or incomplete offline replay cache admitted", drift)
		}
		_ = os.Remove(artifact)
	}
	for _, name := range []string{"../repositories", "/etc/apk/world", "musl-candidate/../repositories", "musl-candidate/a/b.apk", ".", ".."} {
		if validSecurityRuntimeCacheName(name) {
			t.Fatal("unsafe persistent package path accepted", name)
		}
	}
}

func muslArchiveFixture(t *testing.T, version, architecture string, duplicate, symlink bool) []byte {
	t.Helper()
	var output bytes.Buffer
	for _, section := range []string{"signature", "metadata", "data"} {
		compressed := gzip.NewWriter(&output)
		archive := tar.NewWriter(compressed)
		write := func(name, value string, kind byte) {
			header := &tar.Header{Name: name, Mode: 0755, Typeflag: kind, Size: int64(len(value))}
			if kind == tar.TypeSymlink {
				header.Size, header.Linkname = 0, "other"
			}
			if err := archive.WriteHeader(header); err != nil {
				t.Fatal(err)
			}
			if kind != tar.TypeSymlink {
				if _, err := archive.Write([]byte(value)); err != nil {
					t.Fatal(err)
				}
			}
		}
		switch section {
		case "signature":
			write(".SIGN.RSA.reviewed.rsa.pub", "unit parser fixture only", tar.TypeReg)
		case "metadata":
			write(".PKGINFO", fmt.Sprintf("pkgname = musl\npkgver = %s\narch = %s\norigin = musl\n", version, architecture), tar.TypeReg)
		case "data":
			kind := byte(tar.TypeReg)
			if symlink {
				kind = tar.TypeSymlink
			}
			write("lib/ld-musl-"+architecture+".so.1", strings.Repeat("loader bytes", 64), kind)
			if duplicate {
				write("lib/ld-musl-"+architecture+".so.1", strings.Repeat("other bytes", 64), tar.TypeReg)
			}
		}
		if err := archive.Close(); err != nil {
			t.Fatal(err)
		}
		if err := compressed.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return output.Bytes()
}

func TestMuslCandidateArchiveBindsVersionArchitectureAndExactLoader(t *testing.T) {
	for _, architecture := range []string{"x86_64", "aarch64"} {
		data := muslArchiveFixture(t, "1.2.6-r2", architecture, false, false)
		want := legacyWorldHash(strings.Repeat("loader bytes", 64))
		got, err := securityMuslArchiveLoader(context.Background(), bytes.NewReader(data), "1.2.6-r2", architecture)
		if err != nil || got != want {
			t.Fatal("exact concatenated signed APK loader parse failed", got, err)
		}
		for _, bad := range [][]byte{muslArchiveFixture(t, "1.2.6-r3", architecture, false, false), muslArchiveFixture(t, "1.2.6-r2", architecture, true, false), muslArchiveFixture(t, "1.2.6-r2", architecture, false, true), data[:len(data)-4], []byte("unknown archive")} {
			if _, err := securityMuslArchiveLoader(context.Background(), bytes.NewReader(bad), "1.2.6-r2", architecture); err == nil {
				t.Fatal("changed/duplicate/symlink/truncated candidate admitted")
			}
		}
		other := "aarch64"
		if architecture == other {
			other = "x86_64"
		}
		if _, err := securityMuslArchiveLoader(context.Background(), bytes.NewReader(data), "1.2.6-r2", other); err == nil {
			t.Fatal("other architecture candidate admitted")
		}
		ctx, done := context.WithCancel(context.Background())
		done()
		if _, err := securityMuslArchiveLoader(ctx, bytes.NewReader(data), "1.2.6-r2", architecture); err == nil {
			t.Fatal("canceled candidate verification continued")
		}
	}
}

func TestNativeMuslInterruptedOfflineReplay(t *testing.T) {
	if os.Getenv("INCUDAL_SECURITY_MUSL_REPLAY_TEST") != "disposable" || os.Getenv("INCUDAL_COMPAT_RELOAD_SCENARIO") != "empty-pool" {
		t.Skip("disposable original signed old Alpine empty host only")
	}
	ctx, done := context.WithTimeout(context.Background(), 240*time.Second)
	defer done()
	permit := &CompatPermit{RequestID: "11111111-1111-4111-8111-111111111111", HostIdentity: strings.Repeat("a", 64), ExpiresAt: time.Now().Add(240 * time.Second).Format(time.RFC3339Nano)}
	authorize := func(ctx context.Context) error { return authorizeEmptySecurityHost(ctx, permit) }
	for {
		if err := authorize(ctx); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("original empty host did not settle")
		case <-time.After(time.Second):
		}
	}
	// Follow the engine's real order: maintenance first, ordinary tool repair
	// afterwards. Pre-stabilizing world here would hide a completed-receipt
	// retry loop when later tool installation adds a legitimate world atom.
	world, err := readSecurityPackageConstraints("/etc/apk/world")
	if err != nil {
		t.Fatal(err)
	}
	interruption := errors.New("disposable original installation interrupted")
	var prepared securityRuntimeReceipt
	loaderPath, err := securityMuslLoaderPath()
	if err != nil {
		t.Fatal(err)
	}
	loaderOriginal, loaderMode := nativeMuslOriginalFile(t, ctx, loaderPath)
	databaseOriginal, databaseMode := nativeMuslOriginalFile(t, ctx, "/lib/apk/db/installed")
	called := false
	pass, cancel := context.WithTimeout(ctx, 60*time.Second)
	err = repairSecurityPackageTransactionWithInstaller(pass, securityLxcfsTargets, authorize, permit.HostIdentity, func(ctx context.Context, args []string) error {
		called = true
		index, offline := -1, false
		for i, arg := range args {
			if arg == "upgrade" {
				index = i
			}
			if arg == "--no-network" {
				offline = true
			}
		}
		if index < 0 || !offline {
			t.Fatal("original installer did not receive exact offline cache")
		}
		receipt, err := readSecurityRuntimeReceipt(securityRuntimeReceiptPath)
		if err != nil || receipt == nil || receipt.Phase != "prepared" || receipt.Before["musl"] == receipt.Expected["musl"] {
			t.Fatal("signed old-musl fixture or durable original plan missing", err)
		}
		prepared = *receipt
		nativeMuslOriginalCandidateCache(t, ctx, receipt)
		return interruption
	})
	cancel()
	if !called || !errors.Is(err, interruption) {
		t.Fatal("original prepared pre-dispatch interruption not exercised", called, err)
	}
	// Candidate acquisition is an online preparation step. APK 3.0.6 fetch
	// opens without installed state and never marks its cached packages as
	// available offline; upgrade/fix do. Exercise fetch on private copies of
	// the original signed indexes, outside the real installer's 60-second pass.
	// The original sealed cache and all subsequent installers stay offline.
	candidateCheck, candidateDone := context.WithTimeout(ctx, 60*time.Second)
	nativeMuslCandidateFetchGuards(t, candidateCheck, &prepared)
	candidateDone()
	pass, cancel = context.WithTimeout(ctx, 60*time.Second)
	coreInterrupted := false
	err = repairSecurityPackageTransactionWithInstaller(pass, securityLxcfsTargets, authorize, permit.HostIdentity, func(ctx context.Context, args []string) error {
		coreInterrupted = true
		index, offline := -1, false
		for i, arg := range args {
			if arg == "upgrade" {
				index = i
			}
			offline = offline || arg == "--no-network"
		}
		if index < 0 || !offline {
			t.Fatal("original core installer did not retain the offline cache")
		}
		nativeMuslOriginalCandidateCache(t, ctx, &prepared)
		// Use the real signed APK, then restore the exact original registered
		// database snapshot to model the file-before-database durability order.
		// This is a controlled lost-write projection, not a claimed real reboot.
		core := append(append([]string(nil), args[:index+1]...), "musl")
		if _, err := run(ctx, "apk", core...); err != nil {
			t.Fatal("actual original signed core installation failed", err)
		}
		nativeMuslPublishOriginalFile(t, ctx, "/lib/apk/db/installed", databaseOriginal, databaseMode)
		return interruption
	})
	cancel()
	if !coreInterrupted || !errors.Is(err, interruption) {
		t.Fatal("original offline core installation interruption not exercised", coreInterrupted, err)
	}
	output, err := run(ctx, "apk", "info", "-v")
	partial, parseErr := securityInstalledPackages(string(output))
	loader, loaderErr := hashSecurityMuslLoader(ctx)
	if err != nil || parseErr != nil || !reflect.DeepEqual(partial, prepared.Before) || loaderErr != nil || loader != prepared.LoaderExpected {
		t.Fatal("original database-before/signed-file-after interruption fixture not established", err, parseErr, loaderErr)
	}
	pass, cancel = context.WithTimeout(ctx, 60*time.Second)
	fileOrderContinued := false
	err = repairSecurityPackageTransactionWithInstaller(pass, securityLxcfsTargets, authorize, permit.HostIdentity, func(ctx context.Context, args []string) error {
		fileOrderContinued = true
		index, offline := -1, false
		for i, arg := range args {
			if arg == "upgrade" {
				index = i
			}
			offline = offline || arg == "--no-network"
		}
		if index < 0 || !offline {
			t.Fatal("file-before-database replay did not retain the original upgrade")
		}
		nativeMuslOriginalCandidateCache(t, ctx, &prepared)
		core := append(append([]string(nil), args[:index+1]...), "musl")
		if _, err := run(ctx, "apk", core...); err != nil {
			t.Fatal("actual original core replay failed", err)
		}
		// The opposite permitted ordering: an exact original loader before-image
		// with the real signed APK's Expected installed database entry.
		nativeMuslPublishOriginalFile(t, ctx, loaderPath, loaderOriginal, loaderMode)
		return interruption
	})
	cancel()
	if !fileOrderContinued || !errors.Is(err, interruption) {
		t.Fatal("file-before-database original offline replay was rejected", fileOrderContinued, err)
	}
	output, err = run(ctx, "apk", "info", "-v")
	partial, parseErr = securityInstalledPackages(string(output))
	loader, loaderErr = hashSecurityMuslLoader(ctx)
	if err != nil || parseErr != nil || !securityRuntimeInventoryWithin(prepared.Before, prepared.Expected, partial) || partial["musl"] != prepared.Expected["musl"] || reflect.DeepEqual(partial, prepared.Expected) || loaderErr != nil || loader != prepared.LoaderBefore {
		t.Fatal("real signed database-after/original-file-before interruption fixture not established", err, parseErr, loaderErr)
	}
	pass, cancel = context.WithTimeout(ctx, 60*time.Second)
	continued := false
	reinstalled := false
	err = repairSecurityPackageTransactionWithInstaller(pass, securityLxcfsTargets, authorize, permit.HostIdentity, func(ctx context.Context, args []string) error {
		continued = true
		offline := false
		for _, arg := range args {
			offline = offline || arg == "--no-network"
			reinstalled = reinstalled || arg == "fix"
		}
		if !offline {
			t.Fatal("partial original plan reached a network installer")
		}
		_, err := run(ctx, "apk", args...)
		return err
	})
	cancel()
	if err != nil || !continued || !reinstalled {
		t.Fatal("signed original cache could not repair registered payload and complete partial installation", continued, reinstalled, err)
	}
	output, err = run(ctx, "apk", "info", "-v")
	installed, parseErr := securityInstalledPackages(string(output))
	if err != nil || parseErr != nil || !reflect.DeepEqual(installed, prepared.Expected) || verifySecurityPackageConstraints(world) != nil {
		t.Fatal("offline replay did not preserve exact complete plan/world", err, parseErr)
	}
	receipt, err := readSecurityRuntimeReceipt(securityRuntimeReceiptPath)
	if err != nil || receipt == nil || receipt.Phase != "installed" {
		t.Fatal("original signed installation not confirmed", err)
	}
	cache := filepath.Join("/var/lib/incudal-agent", prepared.CacheID)
	if _, err := os.Lstat(cache); !os.IsNotExist(err) {
		t.Fatal("completed exact original cache not cleaned", err)
	}
	pass, cancel = context.WithTimeout(ctx, 60*time.Second)
	err = repairSecurityPackageTransactionWithInstaller(pass, securityLxcfsTargets, authorize, permit.HostIdentity, func(context.Context, []string) error {
		t.Fatal("same-boot confirmed transaction repeated installation")
		return nil
	})
	cancel()
	if err != nil {
		t.Fatal("confirmed installation repeat failed", err)
	}
	installedBeforeRepair, _ := os.ReadFile(securityRuntimeReceiptPath)
	if err := repair(ctx); err != nil {
		t.Fatal("normal post-maintenance tool repair failed", err)
	}
	if err := ensureResourceVisibility(ctx); err != nil {
		t.Fatal("normal post-maintenance resource tool setup failed", err)
	}
	worldAfterRepair, err := readSecurityPackageConstraints("/etc/apk/world")
	if err != nil || bytes.Equal(worldAfterRepair[0].Data, world[0].Data) {
		t.Fatal("old-root fixture did not exercise legitimate post-maintenance world changes", err)
	}
	pass, cancel = context.WithTimeout(ctx, 60*time.Second)
	err = repairEmptyRuntimeSecurityPackages(pass, permit)
	cancel()
	if err != nil || verifySecurityPackageConstraints(worldAfterRepair) != nil {
		t.Fatal("completed receipt permanently refused legitimate later tool constraints", err)
	}
	archive := securityRuntimeReceiptPath + ".installed-" + legacyWorldHash(string(installedBeforeRepair)) + ".json"
	archived, archiveMode, archiveErr := readLegacyWorldFile(archive, true)
	if archiveErr != nil || archiveMode != 0600 || !bytes.Equal(archived, installedBeforeRepair) {
		t.Fatal("new signed plan lost the original completed receipt evidence", archiveErr)
	}
	receipt, err = readSecurityRuntimeReceipt(securityRuntimeReceiptPath)
	if err != nil || receipt == nil || receipt.Environment.Files["/etc/apk/world"] != legacyWorldHash(string(worldAfterRepair[0].Data)) {
		t.Fatal("new signed plan did not retain the actual current world", err)
	}
	t.Log("PASS actual signed APK with controlled exact before-images: both file/database commit orderings, original cache offline payload repair, complete plan/world confirmation, unchanged installed repeat, real maintenance-before-tool-repair order and private prior evidence")
}

func nativeMuslOriginalCandidateCache(t *testing.T, ctx context.Context, receipt *securityRuntimeReceipt) string {
	t.Helper()
	cache, err := verifySecurityRuntimeCache(ctx, receipt)
	if err != nil {
		t.Fatal("original complete signed cache unavailable before interruption", err)
	}
	loader, err := verifyCachedSecurityMuslLoader(ctx, cache, receipt.Expected["musl"])
	if err != nil || loader != receipt.LoaderExpected {
		t.Fatal("original offline candidate signature or exact loader not confirmed", err)
	}
	return cache
}

func nativeMuslCandidateFetchGuards(t *testing.T, ctx context.Context, receipt *securityRuntimeReceipt) {
	t.Helper()
	newCache := func() string {
		t.Helper()
		directory, err := os.MkdirTemp("/var/lib/incudal-agent", ".security-packages-*")
		if err != nil {
			t.Fatal("disposable candidate-check cache unavailable", err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(directory) })
		return directory
	}
	original := nativeMuslOriginalCandidateCache(t, ctx, receipt)
	indexes := newCache()
	indexCount := 0
	for name, want := range receipt.CacheFiles {
		if name != "repositories" && !(strings.HasPrefix(name, "APKINDEX.") && strings.HasSuffix(name, ".tar.gz")) {
			continue
		}
		data, mode := nativeMuslOriginalFile(t, ctx, filepath.Join(original, name))
		copyPath := filepath.Join(indexes, name)
		if err := os.WriteFile(copyPath, data, mode); err != nil {
			t.Fatal("disposable original signed index copy unavailable", err)
		}
		if err := os.Chmod(copyPath, mode); err != nil {
			t.Fatal("disposable original signed index permissions unavailable", err)
		}
		hash, _, err := hashSecurityRuntimeCacheFile(ctx, copyPath)
		if err != nil || hash != want {
			t.Fatal("disposable signed index copy differs from the original receipt", err)
		}
		if name != "repositories" {
			indexCount++
		}
	}
	if indexCount == 0 {
		t.Fatal("original signed indexes missing from the fetch fixture")
	}
	base := []string{"--repositories-file", filepath.Join(indexes, "repositories"), "--cache-dir", indexes, "--cache-max-age", "60", "--wait", "5", "--timeout", "15"}
	version := receipt.Expected["musl"]
	cache := newCache()
	if loader, err := fetchSecurityMuslLoader(ctx, base, cache, version); err != nil || loader != receipt.LoaderExpected {
		t.Fatal("exact original signed musl candidate not fetched during online preparation", err)
	}
	if err := os.WriteFile(filepath.Join(cache, "musl-candidate", "unexpected.apk"), []byte("disposable extra candidate"), 0600); err != nil {
		t.Fatal("disposable extra candidate fixture unavailable", err)
	}
	if _, err := verifyCachedSecurityMuslLoader(ctx, cache, version); err == nil {
		t.Fatal("more than one candidate admitted after successful exact fetch")
	}
	empty := newCache()
	if err := os.Mkdir(filepath.Join(empty, "musl-candidate"), 0700); err != nil {
		t.Fatal("disposable zero-candidate fixture unavailable", err)
	}
	if _, err := verifyCachedSecurityMuslLoader(ctx, empty, version); err == nil {
		t.Fatal("zero candidates admitted without a signed package")
	}
	unavailable := newCache()
	if _, err := fetchSecurityMuslLoader(ctx, base, unavailable, "1.2.6-r999"); err == nil {
		t.Fatal("unavailable exact version admitted after solver failure")
	}
	if files, err := os.ReadDir(filepath.Join(unavailable, "musl-candidate")); err != nil || len(files) != 0 {
		t.Fatal("unavailable exact version produced a substitute candidate", err)
	}
	nativeMuslOriginalCandidateCache(t, ctx, receipt)
	t.Log("PASS actual online preparation using copied original signed indexes: exact version and loader accepted; unavailable version, zero files and extra candidate rejected; original sealed cache unchanged")
}

func nativeMuslOriginalFile(t *testing.T, ctx context.Context, path string) ([]byte, os.FileMode) {
	t.Helper()
	file, err := openCompatFile(path)
	if err != nil {
		t.Fatal("disposable original APK file unavailable", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() > 8388608 || ctx.Err() != nil {
		t.Fatal("disposable original APK file exceeds its fixture budget", err)
	}
	data, err := io.ReadAll(io.LimitReader(file, 8388609))
	if err != nil || len(data) != int(info.Size()) {
		t.Fatal("disposable original APK snapshot is incomplete", err)
	}
	return data, info.Mode().Perm()
}

func nativeMuslPublishOriginalFile(t *testing.T, ctx context.Context, path string, data []byte, mode os.FileMode) {
	t.Helper()
	loader, _ := securityMuslLoaderPath()
	if path != loader && path != "/lib/apk/db/installed" || len(data) == 0 || len(data) > 8388608 || ctx.Err() != nil {
		t.Fatal("disposable write-order fixture target unavailable")
	}
	if _, err := hashCompatFile(ctx, path); err != nil {
		t.Fatal("disposable original destination is unsafe", err)
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".native-musl-write-order-*")
	if err != nil {
		t.Fatal(err)
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
	if err == nil {
		err = os.Rename(file.Name(), path)
	}
	if err != nil {
		t.Fatal("disposable exact before-image publication failed", err)
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		t.Fatal("disposable write-order fixture not durable", err)
	}
}
