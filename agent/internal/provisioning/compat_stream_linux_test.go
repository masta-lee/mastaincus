//go:build linux

package provisioning

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"testing"
	"time"
)

// Full payloads are used only by native lifecycle fixtures, never the Agent.
func compatibilityBinary() ([]byte, error) {
	m, err := compatibilityMetadata()
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	err = streamCompatibilityArtifact(context.Background(), compatibilityFiles, runtime.GOARCH, m, &b)
	return b.Bytes(), err
}
func compatHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func replaceCompatBinary(data []byte) error {
	f, err := os.CreateTemp("/usr/sbin", ".incudal-fixture-incusd-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0755); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	f.Close()
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), "/usr/sbin/incusd")
}
func TestCompatibilityFileHashAndRollbackCopy(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned production file rules; exercised on root native runner")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "incusd")
	backup := filepath.Join(dir, "backup")
	_, _, b := compatFixture("amd64", 1048576)
	if err := os.WriteFile(src, b, 0755); err != nil {
		t.Fatal(err)
	}
	hash := compatHash(b)
	if got, err := hashCompatFile(context.Background(), src); err != nil || got != hash {
		t.Fatal(got, err)
	}
	if err := copyCompatFile(context.Background(), src, backup, hash, false); err != nil {
		t.Fatal(err)
	}
	if got, err := hashCompatFile(context.Background(), backup); err != nil || got != hash {
		t.Fatal("durable backup missing", got, err)
	}
	if err := copyCompatFile(context.Background(), src, backup, hash, false); err == nil {
		t.Fatal("existing backup overwritten")
	}
	for _, kind := range []string{"symlink", "hardlink", "writable"} {
		p := filepath.Join(dir, kind)
		switch kind {
		case "symlink":
			os.Symlink(src, p)
		case "hardlink":
			os.Link(src, p)
		case "writable":
			os.WriteFile(p, b, 0777)
			os.Chmod(p, 0777)
		}
		if _, err := hashCompatFile(context.Background(), p); err == nil {
			t.Fatal("unsafe file accepted", kind)
		}
		os.Remove(p)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := copyCompatFile(ctx, src, filepath.Join(dir, "cancelled"), hash, false); err == nil {
		t.Fatal("cancelled copy accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "cancelled")); !os.IsNotExist(err) {
		t.Fatal("failed copy left partial backup")
	}
}

func TestNativeCompatibilityStatusAllocations(t *testing.T) {
	if os.Getenv("INCUDAL_SYSINFO_COMPAT_TEST") != "disposable" {
		t.Skip("actual pinned Alpine daemon only")
	}
	ctx := context.Background()
	status, _, _ := incusCompatibilityStatus(ctx)
	if status != "verified" {
		t.Fatal("native compatibility not verified", status)
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for n := 0; n < 20; n++ {
		s, _, _ := incusCompatibilityStatus(ctx)
		if s != "verified" {
			t.Fatal("lost daemon proof", s)
		}
	}
	runtime.ReadMemStats(&after)
	perCheck := (after.TotalAlloc - before.TotalAlloc) / 20
	if perCheck > 128*1024 {
		t.Fatalf("verified native status allocated %d bytes/check", perCheck)
	}
	t.Logf("PASS native verified status: %d bytes/check; full installed content hash retained", perCheck)
}

func TestNativeCompatibilityMemoryWorkload(t *testing.T) {
	mode := os.Getenv("INCUDAL_MEMORY_WORKLOAD")
	if mode != "legacy" && mode != "stream" {
		t.Skip("isolated memory workload only")
	}
	metadata, err := compatibilityMetadata()
	if err != nil {
		t.Fatal(err)
	}
	cycles := 20
	if mode == "stream" {
		debug.SetMemoryLimit(60 << 20)
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 0; i < cycles; i++ {
		if mode == "legacy" {
			// Reproduce the prior payload decode and installed-file read. This
			// branch exists only in the isolated test executable, never Agent.
			compressed, e := fs.ReadFile(compatibilityFiles, "compat/incusd-"+runtime.GOARCH+".gz")
			if e != nil {
				t.Fatal(e)
			}
			reader, e := gzip.NewReader(bytes.NewReader(compressed))
			if e != nil {
				t.Fatal(e)
			}
			data, e := io.ReadAll(io.LimitReader(reader, metadata.Size+1))
			reader.Close()
			if e != nil {
				t.Fatal(e)
			}
			installed, e := os.ReadFile("/usr/sbin/incusd")
			if e != nil || compatHash(data) != compatHash(installed) {
				t.Fatal("legacy reference", e)
			}
		} else {
			h, e := hashCompatFile(context.Background(), "/usr/sbin/incusd")
			if e != nil || h != metadata.SHA256 {
				t.Fatal("stream reference", e)
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	runtime.ReadMemStats(&after)
	t.Logf("MEMORY mode=%s cycles=%d alloc=%d heap=%d heapSys=%d gc=%d", mode, cycles, after.TotalAlloc-before.TotalAlloc, after.HeapAlloc, after.HeapSys, after.NumGC-before.NumGC)
}
