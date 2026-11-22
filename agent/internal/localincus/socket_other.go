//go:build !linux

package localincus

import (
	"net"
	"os"
)

func trustedSocket(os.FileInfo) bool        { return false }
func trustedPeerProcess(net.Conn, int) bool { return false }
