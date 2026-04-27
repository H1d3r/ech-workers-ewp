package engine

import (
	"io"
	"sync"

	"ewp-core/common/bufferpool"
)

// pipeTCP copies bytes bidirectionally between an Inbound TCPConn and
// an Outbound TCPConn, then closes both ends. Half-close is not
// supported because TCPConn is intentionally narrow.
func pipeTCP(a, b TCPConn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		buf := bufferpool.GetLarge()
		defer bufferpool.PutLarge(buf)
		_, _ = ioCopyBuf(b, a, buf)
		_ = b.Close()
	}()
	go func() {
		defer wg.Done()
		buf := bufferpool.GetLarge()
		defer bufferpool.PutLarge(buf)
		_, _ = ioCopyBuf(a, b, buf)
		_ = a.Close()
	}()
	wg.Wait()
}

// pipeUDP forwards UDP datagrams bidirectionally between an Inbound
// UDPConn (e.g. TUN-side fake socket) and an Outbound UDPConn (e.g.
// EWP v2 sub-session or a real net.UDPConn).
//
// Both directions preserve the real-remote address: when an Outbound
// reads from upstream, the address it returns flows verbatim into
// the Inbound's WriteTo. This is the linchpin of Full-Cone NAT and
// STUN consistency.
func pipeUDP(in, out UDPConn) {
	var wg sync.WaitGroup
	wg.Add(2)
	// Inbound -> Outbound: client app sends, we forward upstream.
	go func() {
		defer wg.Done()
		buf := bufferpool.GetLarge()
		defer bufferpool.PutLarge(buf)
		for {
			n, src, err := in.ReadFrom(buf)
			if err != nil {
				return
			}
			if err := out.WriteTo(buf[:n], src); err != nil {
				return
			}
		}
	}()
	// Outbound -> Inbound: upstream replies, we hand back with the
	// REAL remote address that the upstream side observed.
	go func() {
		defer wg.Done()
		buf := bufferpool.GetLarge()
		defer bufferpool.PutLarge(buf)
		for {
			n, realRemote, err := out.ReadFrom(buf)
			if err != nil {
				return
			}
			if err := in.WriteTo(buf[:n], realRemote); err != nil {
				return
			}
		}
	}()
	wg.Wait()
	_ = in.Close()
	_ = out.Close()
}

// ioCopyBuf is io.CopyBuffer without the WriterTo/ReaderFrom
// fast-paths; we want full control over the buffer lifecycle so the
// pool returns are predictable.
func ioCopyBuf(dst io.Writer, src io.Reader, buf []byte) (int64, error) {
	var written int64
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				return written, ew
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
		}
		if er != nil {
			if er == io.EOF {
				return written, nil
			}
			return written, er
		}
	}
}
