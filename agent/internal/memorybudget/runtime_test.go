package memorybudget

import (
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"testing"
	"time"
)

func TestNativeAgentBudgetRuntime(t *testing.T) {
	if os.Getenv("INCUDAL_MEMORY_RUNTIME_TEST") != "1" {
		t.Skip("isolated continuous allocation test")
	}
	t.Setenv("GOMEMLIMIT", "")
	old := debug.SetMemoryLimit(-1)
	defer debug.SetMemoryLimit(old)
	limit := Configure()
	if limit < minBudget || limit > maxBudget {
		t.Fatal("automatic startup limit unavailable", limit)
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for n := 0; n < 80; n++ {
		temporary := make([]byte, 8<<20)
		for i := 0; i < len(temporary); i += 4096 {
			temporary[i] = byte(i + n)
		}
		runtime.KeepAlive(temporary)
		time.Sleep(20 * time.Millisecond)
	}
	runtime.ReadMemStats(&after)
	if after.NumGC <= before.NumGC {
		t.Fatal("automatic GC did not run")
	}
	if after.HeapAlloc > uint64(limit)*2 {
		t.Fatalf("soft runtime budget not effective: heap=%d budget=%d", after.HeapAlloc, limit)
	}
	fmt.Printf("PASS persistent Agent startup budget=%d heap=%d cycles=%d gc=%d\n", limit, after.HeapAlloc, 80, after.NumGC-before.NumGC)
}
