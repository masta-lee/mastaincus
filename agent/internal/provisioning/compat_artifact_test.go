package provisioning

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"
)

func compatArtifactHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func compatFixture(arch string, size int) (fstest.MapFS, compatManifest, []byte) {
	b := make([]byte, size)
	copy(b, "\x7fELF")
	machine := uint16(62)
	architecture := "x86_64"
	if arch == "arm64" {
		machine = 183
		architecture = "aarch64"
	}
	binary.LittleEndian.PutUint16(b[18:20], machine)
	m := compatManifest{Purpose: "alpine-incus-sysinfo-compat", IncusVersion: "7.0.1", SourceSha256: "5e415fa1684f0945d45ca780af6662f143b857681e18d29038725cde70c26ee6", LifecycleSourceSha256: "a60cea54e5d1e5397292556627fdcf7a808494e6abcbb180dd3b3710f03eb222", MemorySourceSha256: "fb313cde5dd6d3aeb8a0adc5597726f0625aa404839e38fcf7a12f772dd6eb3c", MemoryBuildDefault: "disablethp=1", MemoryBudgetRevision: "daemon-memory-v1", Architecture: architecture, SHA256: compatArtifactHash(b), Size: int64(size)}
	metadata, _ := json.Marshal(m)
	var compressed bytes.Buffer
	z := gzip.NewWriter(&compressed)
	z.Write(b)
	z.Close()
	return fstest.MapFS{"compat/manifest-" + arch + ".json": {Data: metadata}, "compat/incusd-" + arch + ".gz": {Data: compressed.Bytes()}}, m, b
}
func TestCompatibilityStreamRejectsCorruption(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		files, manifest, _ := compatFixture(arch, 1048576)
		if _, err := validateCompatibilityArtifact(files, arch); err != nil {
			t.Fatal(err)
		}
		for _, change := range []string{"short", "oversize", "checksum", "trailer", "architecture", "cancel", "concatenated"} {
			t.Run(arch+"/"+change, func(t *testing.T) {
				fs, m, b := compatFixture(arch, 1048576)
				ctx := context.Background()
				switch change {
				case "short":
					m.Size++
				case "oversize":
					m.Size--
				case "checksum":
					m.SHA256 = strings.Repeat("0", 64)
				case "architecture":
					b[18] ^= 1
					var out bytes.Buffer
					z := gzip.NewWriter(&out)
					z.Write(b)
					z.Close()
					fs["compat/incusd-"+arch+".gz"].Data = out.Bytes()
				case "trailer":
					raw := fs["compat/incusd-"+arch+".gz"].Data
					raw[len(raw)-5] ^= 1
				case "cancel":
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(ctx)
					cancel()
				case "concatenated":
					var extra bytes.Buffer
					z := gzip.NewWriter(&extra)
					z.Write([]byte("extra"))
					z.Close()
					fs["compat/incusd-"+arch+".gz"].Data = append(fs["compat/incusd-"+arch+".gz"].Data, extra.Bytes()...)
				}
				if err := streamCompatibilityArtifact(ctx, fs, arch, m, io.Discard); err == nil {
					t.Fatal("unsafe stream accepted")
				}
			})
		}
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		for n := 0; n < 5; n++ {
			if err := streamCompatibilityArtifact(context.Background(), files, arch, manifest, io.Discard); err != nil {
				t.Fatal(err)
			}
		}
		runtime.ReadMemStats(&after)
		if allocated := (after.TotalAlloc - before.TotalAlloc) / 5; allocated > 256*1024 {
			t.Fatalf("stream allocated %d bytes per check", allocated)
		}
	}
}

func BenchmarkCompatibilityStreamingPayload(b *testing.B) {
	files, m, _ := compatFixture(runtime.GOARCH, 64*1024*1024)
	b.ReportAllocs()
	b.SetBytes(m.Size)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := streamCompatibilityArtifact(context.Background(), files, runtime.GOARCH, m, io.Discard); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCompatibilityLegacyPayload(b *testing.B) {
	files, m, _ := compatFixture(runtime.GOARCH, 64*1024*1024)
	b.ReportAllocs()
	b.SetBytes(m.Size)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		compressed, err := fs.ReadFile(files, "compat/incusd-"+runtime.GOARCH+".gz")
		if err != nil {
			b.Fatal(err)
		}
		z, err := gzip.NewReader(bytes.NewReader(compressed))
		if err != nil {
			b.Fatal(err)
		}
		payload, err := io.ReadAll(io.LimitReader(z, m.Size+1))
		z.Close()
		if err != nil || compatArtifactHash(payload) != m.SHA256 {
			b.Fatal("legacy reference failed", err)
		}
	}
}
