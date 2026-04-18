//go:build linux
// +build linux

package net

import (
	"syscall"

	"ewp-core/log"
)

const (
	TCP_FASTOPEN = 23 // TCP_FASTOPEN socket option for Linux
)

// enableTFO enables TCP Fast Open socket option (Linux implementation)
// P2-38: Note that this only sets the socket option, it does NOT send data in SYN packet
func enableTFO(fd int) error {
	// Linux kernel 3.7+ supports TCP Fast Open
	// Set TCP_FASTOPEN socket option with queue length
	// Note: This enables TFO at socket level, but actual TFO requires sendto with MSG_FASTOPEN
	err := syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, TCP_FASTOPEN, 5)
	if err != nil {
		log.V("[TFO] Failed to set TCP_FASTOPEN socket option on Linux: %v", err)
		return err
	}

	log.V("[TFO] TCP_FASTOPEN socket option enabled on fd %d (Linux, socket-level only)", fd)
	return nil
}

// enableTFOListener enables TCP Fast Open on a listener socket (Linux implementation)
func enableTFOListener(fd int) error {
	// Linux kernel 3.7+ supports TCP Fast Open for server sockets
	// The value is the max queue length for pending TFO connections
	// Typical values: 5-128
	err := syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, TCP_FASTOPEN, 128)
	if err != nil {
		log.V("[TFO] Failed to set TCP_FASTOPEN on listener (Linux): %v", err)
		return err
	}

	log.V("[TFO] TCP_FASTOPEN enabled on listener fd %d (Linux, queue=128)", fd)
	return nil
}
