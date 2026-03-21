package ewp

import (
	"io"
	"sync"
)

// flowReadPool provides reusable read buffers for FlowReader.Read.
// Default size matches the typical TCP read buffer used by callers (32 KB).
// The pool buffer is capped to len(p) on each call, so n ≤ len(p) always
// holds and XtlsUnpadding output ≤ input ≤ len(p) — copy never truncates.
var flowReadPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 32*1024)
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
type FlowReader struct {
	reader   io.Reader
	state    *FlowState
	isUplink bool
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
// The pool buffer is capped to len(p) bytes. ProcessUplink/ProcessDownlink strip
// padding so output ≤ input ≤ len(p) — copy never truncates.
func (r *FlowReader) Read(p []byte) (n int, err error) {
	if r.state == nil || r.state.ShouldDirectCopy(!r.isUplink) {
		return r.reader.Read(p)
	}

	bufp := flowReadPool.Get().(*[]byte)
	buf := *bufp
	if len(buf) < len(p) {
		buf = make([]byte, len(p))
	}

	n, err = r.reader.Read(buf[:len(p)])
	if n == 0 {
		*bufp = buf
		flowReadPool.Put(bufp)
		return 0, err
	}

	var unpadded []byte
	if r.isUplink {
		unpadded = r.state.ProcessUplink(buf[:n])
	} else {
		unpadded = r.state.ProcessDownlink(buf[:n])
	}

	copied := copy(p, unpadded)
	*bufp = buf
	flowReadPool.Put(bufp)
	return copied, err
}

// Close closes the underlying reader if it implements io.Closer
func (r *FlowReader) Close() error {
	if closer, ok := r.reader.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
