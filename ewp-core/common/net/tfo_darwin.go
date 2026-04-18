//go:build darwin

package net

import (
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	TCP_FASTOPEN = 0x105
)

// enableTFO enables TCP Fast Open socket option (macOS implementation)
// P2-38: Note that this only sets the socket option, it does NOT send data in SYN packet
func enableTFO(fd int) error {
	// macOS 10.11+ supports TCP Fast Open
	// Note: This enables TFO at socket level, but actual TFO requires connectx() with data
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, TCP_FASTOPEN, 1)
}

// enableTFOListener enables TCP Fast Open on a listener socket (macOS implementation)
func enableTFOListener(fd int) error {
	// macOS 10.11+ supports TCP Fast Open for server sockets
	return unix.SetsockoptInt(fd, unix.IPPROTO_TCP, TCP_FASTOPEN, 1)
}
