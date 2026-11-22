//go:build linux

package localincus

import (
	"net"
	"os"
	"syscall"
)

func trustedPeerProcess(connection net.Conn, pid int) bool {
	unix, ok := connection.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := unix.SyscallConn()
	if err != nil {
		return false
	}
	var credentials *syscall.Ucred
	var failed error
	if err = raw.Control(func(fd uintptr) {
		credentials, failed = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || failed != nil || credentials == nil {
		return false
	}
	return credentials.Uid == 0 && int(credentials.Pid) == pid
}

func trustedSocket(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && info.Mode()&os.ModeSocket != 0
}
