// Native build probe; never included in the released daemon or customer image.
package main

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"unsafe"
)

func main() {
	data := make([]byte, 32<<20)
	for i := 0; i < len(data); i += 4096 {
		data[i] = 1
	}
	addr := uint64(uintptr(unsafe.Pointer(&data[0])))
	smaps, err := os.ReadFile("/proc/self/smaps")
	if err != nil {
		panic(err)
	}
	found, noHuge := false, false
	inside := false
	for _, line := range strings.Split(string(smaps), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if bounds := strings.Split(fields[0], "-"); len(bounds) == 2 {
			start, e1 := strconv.ParseUint(bounds[0], 16, 64)
			end, e2 := strconv.ParseUint(bounds[1], 16, 64)
			inside = e1 == nil && e2 == nil && start <= addr && addr < end
		}
		if inside && fields[0] == "VmFlags:" {
			found = true
			for _, flag := range fields[1:] {
				if flag == "nh" {
					noHuge = true
				}
			}
		}
	}
	runtime.KeepAlive(data)
	want := os.Getenv("INCUDAL_EXPECT_SMALL_PAGES") == "1"
	if !found || noHuge != want {
		panic(fmt.Sprintf("Go heap small pages=%v expected=%v found=%v", noHuge, want, found))
	}
	fmt.Printf("PASS native Go heap no-hugepage=%v, explicit operator default respected\n", noHuge)
}
