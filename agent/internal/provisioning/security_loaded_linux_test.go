//go:build linux

package provisioning

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestSecurityLoadedStateExcludesGuestsAndSharedMemory(t *testing.T) {
	root := t.TempDir()
	for _, pid := range []string{"1", "2", "3"} {
		os.MkdirAll(filepath.Join(root, pid, "ns"), 0700)
		ns := "pid:[1]"
		if pid == "3" {
			ns = "pid:[3]"
		}
		os.Symlink(ns, filepath.Join(root, pid, "ns/pid"))
		os.WriteFile(filepath.Join(root, pid, "maps"), []byte("a-b rw-s 0 0 0 /dev/zero (deleted)\na-b r-xp 0 0 0 /memfd:jit (deleted)\n"), 0600)
	}
	os.WriteFile(filepath.Join(root, "3/maps"), []byte("a-b r-xp 0 0 0 /guest-private.so (deleted)\n"), 0600)
	state, err := securityLoadedState(context.Background(), root)
	if err != nil || state != "checked" {
		t.Fatal(state, err)
	}
	if old, err := securityProcessLoaded(context.Background(), root, 2); err != nil || old {
		t.Fatal(old, err)
	}
	if _, err := securityProcessLoaded(context.Background(), root, 3); err == nil {
		t.Fatal("guest namespace accepted for host activation")
	}
	os.WriteFile(filepath.Join(root, "2/maps"), []byte("a-b r-xp 0 0 0 /host-private.so (deleted)\n"), 0600)
	state, err = securityLoadedState(context.Background(), root)
	if err != nil || state != "activation-required" {
		t.Fatal(state, err)
	}
	if old, err := securityProcessLoaded(context.Background(), root, 2); err != nil || !old {
		t.Fatal(old, err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = securityLoadedState(canceled, root); err == nil {
		t.Fatal("canceled scan accepted")
	}
}
