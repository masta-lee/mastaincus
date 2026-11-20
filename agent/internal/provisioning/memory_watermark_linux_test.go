//go:build linux

package provisioning

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

func TestSmallHostMemoryReserveScope(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  int64
	}{
		{"MemTotal: 989376 kB", 8192},
		{"MemTotal: 1048576 kB", 8192},
		{"MemTotal: 1048577 kB", 0},
		{"MemTotal: 8388608 kB", 0},
		{"MemTotal: 500000 kB", 0},
		{"MemTotal: -1 kB", 0},
		{"MemTotal: 989376 MB", 0},
	} {
		if got := smallHostWatermark(tc.input); got != tc.want {
			t.Fatalf("%q: got %d want %d", tc.input, got, tc.want)
		}
	}
	for _, input := range []string{"vm.min_free_kbytes=45056", "-vm.min_free_kbytes = 45056", "vm/min_free_kbytes = 20000"} {
		if !operatorWatermark(map[string]string{"/etc/sysctl.conf": input}) {
			t.Fatal("explicit administrator reserve lost", input)
		}
	}
	if operatorWatermark(map[string]string{"/etc/sysctl.conf": "# vm.min_free_kbytes=45056\nvm.swappiness=60", memoryWatermarkFile: watermarkConfig(8192)}) {
		t.Fatal("comment or owned policy mistaken for external override")
	}
}

func TestNativeMemoryReservePersistenceAndOverrides(t *testing.T) {
	if os.Getenv("INCUDAL_MEMORY_PRESSURE_TEST") != "disposable" || os.Geteuid() != 0 {
		t.Skip("disposable aggregate fixture only")
	}
	for _, path := range []string{memoryWatermarkFile, memoryWatermarkJournal, "/etc/sysctl.d/92-fixture-reserve.conf"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("fixture must start without a policy", path)
		}
	}
	old, err := os.ReadFile("/proc/sys/vm/min_free_kbytes")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		os.WriteFile("/proc/sys/vm/min_free_kbytes", old, 0644)
		os.Remove(memoryWatermarkFile)
		os.Remove(memoryWatermarkJournal)
		os.Remove("/etc/sysctl.d/92-fixture-reserve.conf")
	}()
	if err := os.WriteFile("/proc/sys/vm/min_free_kbytes", []byte("45056"), 0644); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := applyStandaloneMemoryWatermark(ctx, 8192); err != nil {
		t.Fatal("native policy", err)
	}
	config, err := os.ReadFile(memoryWatermarkFile)
	if err != nil || string(config) != watermarkConfig(8192) {
		t.Fatal("persistent policy missing", err)
	}
	receipt, err := os.ReadFile(memoryWatermarkJournal)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyStandaloneMemoryWatermark(ctx, 8192); err != nil {
		t.Fatal("idempotent policy", err)
	}
	currentReceipt, _ := os.ReadFile(memoryWatermarkJournal)
	if string(receipt) != string(currentReceipt) {
		t.Fatal("normal periodic pass rewrote original receipt")
	}
	var previousBoot memoryWatermarkReceipt
	if err := json.Unmarshal(receipt, &previousBoot); err != nil {
		t.Fatal(err)
	}
	previousBoot.BootID = "11111111-1111-4111-8111-111111111111"
	stale, _ := json.Marshal(previousBoot)
	os.WriteFile(memoryWatermarkJournal, stale, 0600)
	if err := applyStandaloneMemoryWatermark(ctx, 8192); err != nil {
		t.Fatal("new boot receipt", err)
	}
	currentReceipt, _ = os.ReadFile(memoryWatermarkJournal)
	var newBoot memoryWatermarkReceipt
	json.Unmarshal(currentReceipt, &newBoot)
	if newBoot.BootID == previousBoot.BootID {
		t.Fatal("boot-applied policy left stale receipt and could overwrite later operator changes")
	}
	os.WriteFile("/proc/sys/vm/min_free_kbytes", []byte("20000"), 0644)
	if err := applyStandaloneMemoryWatermark(ctx, 8192); err != nil {
		t.Fatal(err)
	}
	current, _ := os.ReadFile("/proc/sys/vm/min_free_kbytes")
	if string(current) != "20000\n" {
		t.Fatal("later runtime operator setting overwritten")
	}
	os.WriteFile("/etc/sysctl.d/92-fixture-reserve.conf", []byte("vm.min_free_kbytes=25000\n"), 0644)
	if err := applyStandaloneMemoryWatermark(ctx, 8192); err != nil {
		t.Fatal(err)
	}
	current, _ = os.ReadFile("/proc/sys/vm/min_free_kbytes")
	if string(current) != "20000\n" {
		t.Fatal("persistent operator setting overwritten")
	}
	if _, err := os.Lstat(memoryWatermarkFile); !os.IsNotExist(err) {
		t.Fatal("owned policy would override earlier administrator configuration at boot")
	}
	os.Remove("/etc/sysctl.d/92-fixture-reserve.conf")
	os.WriteFile(memoryWatermarkFile, []byte("# changed by operator\nvm.min_free_kbytes=20000\n"), 0644)
	if err := applyStandaloneMemoryWatermark(ctx, 8192); err == nil {
		t.Fatal("modified owned config overwritten")
	}
	t.Log("real sysctl, durable policy, repeat, runtime/persistent override and drift guards confirmed")
}
