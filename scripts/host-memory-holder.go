// A bounded disposable customer workload; not shipped with the product.
package main

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"time"
)

func main() {
	n, err := strconv.Atoi(os.Args[1])
	if err != nil || n <= 0 || n > 768<<20 {
		panic("invalid disposable memory size")
	}
	b := make([]byte, n)
	for i := 0; i < len(b); i += 4096 {
		b[i] = 0x5a
	}
	fmt.Println("MEMORY_HOLDER_READY")
	for {
		for i := 0; i < len(b); i += 4096 {
			if b[i] != 0x5a {
				panic("memory contents changed")
			}
		}
		runtime.KeepAlive(b)
		time.Sleep(time.Second)
	}
}
