//go:build !linux

package localincus

import "os"

func trustedSocket(os.FileInfo) bool { return false }
