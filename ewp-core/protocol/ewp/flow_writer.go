package ewp

import (
	"io"
	"sync"
)

// flowReadPool provides reusable read buffers for FlowReader.Read.
// Pre-sized to 2× MaxPayloadLength to accommodate the largest possible
// padded frame without a per-call make().
//
// The buffer is returned to the pool only after copy() and overflow extraction
// are complete — never before ProcessUplink/ProcessDownlink finishes reading it.
var flowReadPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 2*MaxPayloadLength)
		return &b
	},
}

// FlowWriter wraps a writer and applies Vision-style padding
type FlowWriter struct {
	writer            io.Writer
	state             *FlowState
	isUplink          bool
	writeOnceUserUUID []byte
}

// NewFlowWriter creates a new flow writer
func NewFlowWriter(writer io.Writer, state *FlowState, isUplink bool) *FlowWriter {
	// Copy UserUUID for one-time write
	uuidCopy := make([]byte, len(state.UserUUID))
	copy(uuidCopy, state.UserUUID)

	return &FlowWriter{
		writer:            writer,
		state:             state,
		isUplink:          isUplink,
		writeOnceUserUUID: uuidCopy,
	}
}

// Write writes padded data
func (w *FlowWriter) Write(p []byte) (n int, err error) {
	if w.state == nil {
		return w.writer.Write(p)
	}

	// Check if should switch to direct copy
	if w.state.ShouldDirectCopy(w.isUplink) {
		return w.writer.Write(p)
	}

	// Apply padding
	var padded []byte
	if w.isUplink {
		padded = w.state.PadUplink(p, &w.writeOnceUserUUID)
	} else {
		padded = w.state.PadDownlink(p, &w.writeOnceUserUUID)
	}

	_, err = w.writer.Write(padded)
	if err != nil {
		return 0, err
	}

	return len(p), nil // Return original length
}

// Close closes the underlying writer if it implements io.Closer
func (w *FlowWriter) Close() error {
	if closer, ok := w.writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// FlowReader wraps a reader and removes Vision-style padding.
//
// overflow holds unpadded bytes that exceeded p's capacity on a previous Read.
// These bytes were already consumed from the underlying reader and must be
// delivered before making any new IO call; without this field they are silently
// dropped, desynchronising the TCP stream and causing download errors.
type FlowReader struct {
	reader   io.Reader
	state    *FlowState
	isUplink bool
	overflow []byte // leftover unpadded bytes not delivered on the previous call
}

// NewFlowReader creates a new flow reader
func NewFlowReader(reader io.Reader, state *FlowState, isUplink bool) *FlowReader {
	return &FlowReader{
		reader:   reader,
		state:    state,
		isUplink: isUplink,
	}
}

// Read reads and unpads data.
//
// Overflow contract: because the underlying reader is called with a buffer
// twice the size of p (to absorb the largest possible padded frame), the
// unpadded result can exceed len(p). Excess bytes are saved in r.overflow and
// drained on the next call — they must never be discarded.
//
// Pool contract: the pool buffer is returned only after all reads from it are
// complete (ProcessUplink/ProcessDownlink + overflow copy), preventing the
// use-after-pool-return race that caused packet corruption.
func (r *FlowReader) Read(p []byte) (n int, err error) {
	// Drain overflow before any IO — these bytes are already owned by the caller.
	if len(r.overflow) > 0 {
		n = copy(p, r.overflow)
		r.overflow = r.overflow[n:]
		if len(r.overflow) == 0 {
			r.overflow = nil
		}
		return n, nil
	}

	if r.state == nil || r.state.ShouldDirectCopy(!r.isUplink) {
		return r.reader.Read(p)
	}

	// Acquire a pooled buffer; grow if p is unusually large.
	bufp := flowReadPool.Get().(*[]byte)
	buf := *bufp
	need := len(p) * 2
	if len(buf) < need {
		buf = make([]byte, need)
	}

	n, err = r.reader.Read(buf)
	// Per io.Reader contract: a reader may return n > 0 AND a non-nil error
	// (including io.EOF) in the same call. Process the n bytes first; surface
	// the error only after all data has been delivered to the caller.
	readErr := err
	if n == 0 {
		*bufp = buf
		flowReadPool.Put(bufp)
		return 0, readErr
	}

	var unpadded []byte
	if r.isUplink {
		unpadded = r.state.ProcessUplink(buf[:n])
	} else {
		unpadded = r.state.ProcessDownlink(buf[:n])
	}

	copied := copy(p, unpadded)

	// Save any excess into r.overflow before returning the pool buffer.
	// unpadded may alias buf (ProcessUplink returns buf[:n] when no padding
	// is active), so the copy must happen before Put.
	// If there is overflow, suppress readErr until the overflow is drained —
	// returning EOF while data is still pending would cause the caller to stop.
	if copied < len(unpadded) {
		r.overflow = make([]byte, len(unpadded)-copied)
		copy(r.overflow, unpadded[copied:])
		readErr = nil
	}

	*bufp = buf
	flowReadPool.Put(bufp)
	return copied, readErr
}

// Close closes the underlying reader if it implements io.Closer
func (r *FlowReader) Close() error {
	if closer, ok := r.reader.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
