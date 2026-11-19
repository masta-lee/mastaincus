//go:build linux

package localincus

import (
	"os"
	"syscall"
)

func trustedSocket(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && info.Mode()&os.ModeSocket != 0
}
