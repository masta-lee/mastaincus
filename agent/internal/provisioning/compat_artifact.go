package provisioning

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"runtime"
	"sync"
)

//go:embed compat/README.txt
var compatibilityFiles embed.FS

type compatManifest struct {
	Purpose, IncusVersion, SourceSha256, Architecture, SHA256    string
	LifecycleSourceSha256                                        string
	MemorySourceSha256, MemoryBuildDefault, MemoryBudgetRevision string
	MemoryNamespaceSourceSha256                                  string
	MemoryRaftSourceSha256                                       string
	Size                                                         int64
}

const compatMaxBinaryBytes = 96 * 1024 * 1024
const compatStreamBufferBytes = 32 * 1024

var compatibilityMetadataOnce sync.Once
var compatibilityMetadataValue compatManifest
var compatibilityMetadataError error

// Validate the immutable embedded artifact once, retaining only its small
// manifest. No decompressed binary survives a check or a repair operation.
func compatibilityMetadata() (compatManifest, error) {
	compatibilityMetadataOnce.Do(func() {
		compatibilityMetadataValue, compatibilityMetadataError = validateCompatibilityArtifact(compatibilityFiles, runtime.GOARCH)
	})
	return compatibilityMetadataValue, compatibilityMetadataError
}

func validateCompatibilityArtifact(files fs.FS, arch string) (compatManifest, error) {
	var manifest compatManifest
	data, err := fs.ReadFile(files, "compat/manifest-"+arch+".json")
	if err != nil {
		return manifest, err
	}
	if len(data) > 16384 || json.Unmarshal(data, &manifest) != nil ||
		manifest.Purpose != "alpine-incus-sysinfo-compat" || manifest.IncusVersion != "7.0.1" ||
		manifest.SourceSha256 != "5e415fa1684f0945d45ca780af6662f143b857681e18d29038725cde70c26ee6" ||
		manifest.LifecycleSourceSha256 != "a60cea54e5d1e5397292556627fdcf7a808494e6abcbb180dd3b3710f03eb222" ||
		manifest.MemorySourceSha256 != "56b95831a97677406958326f0a2d42a1aebc4589ebab8c616d9e735df2194f63" ||
		manifest.MemoryNamespaceSourceSha256 != "917e33a02226b436dd6724c59fdc04735cc7958a1ffa33bd80f5084b39fa2ed1" ||
		manifest.MemoryRaftSourceSha256 != "1ff2c7651926aab3f7a5eb78d5cb481a5c2902a0b4ca102253e50e4c3fb99136" ||
		manifest.MemoryBuildDefault != "disablethp=1" || manifest.MemoryBudgetRevision != "daemon-memory-v3" ||
		manifest.Size < 20 || manifest.Size > compatMaxBinaryBytes || len(manifest.SHA256) != 64 {
		return manifest, fmt.Errorf("compatibility manifest invalid")
	}
	if _, err = hex.DecodeString(manifest.SHA256); err != nil {
		return manifest, fmt.Errorf("compatibility manifest invalid")
	}
	expected := "x86_64"
	if arch == "arm64" {
		expected = "aarch64"
	} else if arch != "amd64" {
		return manifest, fmt.Errorf("compatibility architecture unsupported")
	}
	if manifest.Architecture != expected {
		return manifest, fmt.Errorf("compatibility manifest invalid")
	}
	if err = streamCompatibilityArtifact(context.Background(), files, arch, manifest, io.Discard); err != nil {
		return manifest, err
	}
	return manifest, nil
}

func streamCompatibilityArtifact(ctx context.Context, files fs.FS, arch string, manifest compatManifest, output io.Writer) error {
	compressed, err := files.Open("compat/incusd-" + arch + ".gz")
	if err != nil {
		return err
	}
	defer compressed.Close()
	reader, err := gzip.NewReader(compressed)
	if err != nil {
		return err
	}
	defer reader.Close()
	var header [20]byte
	if _, err = io.ReadFull(reader, header[:]); err != nil {
		return fmt.Errorf("compatibility artifact invalid")
	}
	machine := uint16(62)
	if arch == "arm64" {
		machine = 183
	}
	if string(header[:4]) != "\x7fELF" || binary.LittleEndian.Uint16(header[18:20]) != machine {
		return fmt.Errorf("compatibility artifact invalid")
	}
	hash := sha256.New()
	w := io.MultiWriter(output, hash)
	if _, err = w.Write(header[:]); err != nil {
		return err
	}
	n, err := copyCompatBytes(ctx, w, reader, manifest.Size-int64(len(header)))
	if err != nil || n != manifest.Size-int64(len(header)) || hex.EncodeToString(hash.Sum(nil)) != manifest.SHA256 {
		if err != nil {
			return err
		}
		return fmt.Errorf("compatibility artifact invalid")
	}
	return nil
}

// Probe the byte after the limit, including gzip trailers and concatenated
// members. A short, oversized, corrupt or cancelled stream is never accepted.
func copyCompatBytes(ctx context.Context, dst io.Writer, src io.Reader, limit int64) (int64, error) {
	if limit < 0 || limit > compatMaxBinaryBytes {
		return 0, fmt.Errorf("compatibility size invalid")
	}
	buffer := make([]byte, compatStreamBufferBytes)
	var total int64
	for total < limit {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		chunk := int64(len(buffer))
		if chunk > limit-total {
			chunk = limit - total
		}
		n, err := src.Read(buffer[:chunk])
		if n > 0 {
			written, writeErr := dst.Write(buffer[:n])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
			if written != n {
				return total, io.ErrShortWrite
			}
		}
		if err != nil {
			if err == io.EOF {
				return total, nil
			}
			return total, err
		}
		if n == 0 {
			return total, io.ErrNoProgress
		}
	}
	if err := ctx.Err(); err != nil {
		return total, err
	}
	var extra [1]byte
	if n, err := io.ReadFull(src, extra[:]); n != 0 {
		return total, fmt.Errorf("compatibility artifact exceeds limit")
	} else if err != io.EOF {
		return total, err
	}
	return total, nil
}
