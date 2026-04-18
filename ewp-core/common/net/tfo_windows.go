//go:build windows
// +build windows

package net

import (
	"syscall"

	"ewp-core/log"
)

const (
	TCP_FASTOPEN = 15 // TCP_FASTOPEN socket option for Windows
)

// enableTFO enables TCP Fast Open socket option (Windows implementation)
// P2-38: Note that this only sets the socket option, it does NOT send data in SYN packet
func enableTFO(fd int) error {
	// Windows 10 (version 1607+) supports TCP Fast Open
	// Set TCP_FASTOPEN socket option
	// Note: This enables TFO at socket level, but actual TFO requires ConnectEx with data
	err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_TCP, TCP_FASTOPEN, 1)
	if err != nil {
		log.V("[TFO] Failed to set TCP_FASTOPEN socket option on Windows: %v", err)
		return err
	}

	log.V("[TFO] TCP_FASTOPEN socket option enabled on fd %d (Windows, socket-level only)", fd)
	return nil
}

// enableTFOListener enables TCP Fast Open on a listener socket (Windows implementation)
func enableTFOListener(fd int) error {
	// Windows 10 (version 1607+) supports TCP Fast Open for server sockets
	// Set TCP_FASTOPEN socket option
	err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_TCP, TCP_FASTOPEN, 1)
	if err != nil {
		log.V("[TFO] Failed to set TCP_FASTOPEN on listener (Windows): %v", err)
		return err
	}

	log.V("[TFO] TCP_FASTOPEN enabled on listener fd %d (Windows)", fd)
	return nil
}
