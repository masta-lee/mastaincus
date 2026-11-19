//go:build linux

package provisioning

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"runtime"
	"syscall"
)

func openCompatFile(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	s, err := f.Stat()
	if err != nil || !s.Mode().IsRegular() || s.Size() < 20 || s.Size() > compatMaxBinaryBytes ||
		s.Mode()&0022 != 0 || s.Sys().(*syscall.Stat_t).Uid != 0 || s.Sys().(*syscall.Stat_t).Nlink != 1 {
		f.Close()
		return nil, fmt.Errorf("compatibility binary unsafe")
	}
	return f, nil
}

func hashCompatReader(ctx context.Context, f *os.File) (string, error) {
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() < 20 || before.Size() > compatMaxBinaryBytes {
		return "", fmt.Errorf("compatibility binary invalid")
	}
	hash := sha256.New()
	n, err := copyCompatBytes(ctx, hash, f, before.Size())
	if err != nil {
		return "", fmt.Errorf("compatibility binary read failed: %w", err)
	}
	if n != before.Size() {
		return "", fmt.Errorf("compatibility binary truncated")
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() ||
		before.ModTime() != after.ModTime() || before.Sys().(*syscall.Stat_t).Ctim != after.Sys().(*syscall.Stat_t).Ctim {
		return "", fmt.Errorf("compatibility binary changed during read")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func hashCompatFile(ctx context.Context, path string) (string, error) {
	f, err := openCompatFile(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	return hashCompatReader(ctx, f)
}

func stageCompatibilityBinary(ctx context.Context) (string, error) {
	manifest, err := compatibilityMetadata()
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp("/usr/sbin", ".incudal-incusd-*")
	if err != nil {
		return "", err
	}
	name := f.Name()
	if err = streamCompatibilityArtifact(ctx, compatibilityFiles, runtime.GOARCH, manifest, f); err == nil {
		err = f.Chmod(0755)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}

func copyCompatFile(ctx context.Context, source, target, expectedHash string, replace bool) error {
	src, err := openCompatFile(source)
	if err != nil {
		return err
	}
	defer src.Close()
	before, err := src.Stat()
	if err != nil {
		return err
	}
	var dst *os.File
	if replace {
		dst, err = os.CreateTemp("/usr/sbin", ".incudal-incusd-*")
	} else {
		dst, err = os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	}
	if err != nil {
		return err
	}
	name := dst.Name()
	keep := false
	defer func() {
		if !keep {
			os.Remove(name)
		}
	}()
	hash := sha256.New()
	n, err := copyCompatBytes(ctx, io.MultiWriter(dst, hash), src, before.Size())
	after, statErr := src.Stat()
	if err == nil && (statErr != nil || n != before.Size() || hex.EncodeToString(hash.Sum(nil)) != expectedHash ||
		before.ModTime() != after.ModTime() || before.Sys().(*syscall.Stat_t).Ctim != after.Sys().(*syscall.Stat_t).Ctim) {
		err = fmt.Errorf("compatibility source changed during copy")
	}
	mode := os.FileMode(0700)
	if replace {
		mode = 0755
	}
	if err == nil {
		err = dst.Chmod(mode)
	}
	if err == nil {
		err = dst.Sync()
	}
	if closeErr := dst.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if replace {
		return os.Rename(name, target)
	}
	// The exclusive rollback copy is durable and must outlive this call.
	keep = true
	return nil
}
