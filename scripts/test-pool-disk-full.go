// Disposable native quota probe. Not included in runtime packages.
package main

import (
	"fmt"
	"os"
	"syscall"
)

func main() {
	if len(os.Args) != 2 || os.Args[1] != "disposable-10gib-volume" {
		panic("disposable independent disk fixture required")
	}
	const path = "/root/quota-check-fixture"
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		panic(err)
	}
	defer os.Remove(path)
	defer file.Close()
	// Reserve actual extents, not a sparse truncate. This must hit the private
	// 10GiB device's ENOSPC boundary without writing 11GiB on a busy CI disk.
	err = syscall.Fallocate(int(file.Fd()), 0, 0, 11<<30)
	if err != syscall.ENOSPC && err != syscall.EDQUOT {
		panic(fmt.Sprintf("private filesystem did not enforce capacity: %v", err))
	}
	if err := file.Sync(); err != nil {
		panic(err)
	}
	fmt.Println("PRIVATE_DEVICE_CAPACITY_ENFORCED")
}
