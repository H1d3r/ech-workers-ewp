package masque

// Performance regression tests for MASQUE conn hot paths.
//
// Run:
//   go test -race -count=1 -run TestPerf ./transport/masque/...
//   go test -bench=. -benchmem -run=^$ ./transport/masque/...
//
// T8  context-id fast-path — stripContextID

import (
	"testing"
)

// ── T8: stripContextID fast-path ──────────────────────────────────────────────

// TestStripContextID_Zero verifies the happy path: a datagram starting with
// 0x00 returns the payload without the prefix byte.
//
// RED: stripContextID panics (not implemented).
func TestStripContextID_Zero(t *testing.T) {
	payload := []byte{0x00, 0xDE, 0xAD, 0xBE, 0xEF}
	got, err := stripContextID(payload)
	if err != nil {
		t.Fatalf("stripContextID: unexpected error: %v", err)
	}
	want := payload[1:]
	if string(got) != string(want) {
		t.Fatalf("stripContextID = %v, want %v", got, want)
	}
}

// TestStripContextID_EmptyInput verifies that an empty slice returns an error
// rather than panicking.
//
// RED: stripContextID panics (not implemented).
func TestStripContextID_EmptyInput(t *testing.T) {
	_, err := stripContextID([]byte{})
	if err == nil {
		t.Fatal("expected error for empty datagram, got nil")
	}
}

// TestStripContextID_NonZeroContextID verifies that a datagram with context-id
// ≠ 0 returns an error (we only support context-id=0 per RFC 9298 §4).
//
// RED: stripContextID panics (not implemented).
func TestStripContextID_NonZeroContextID(t *testing.T) {
	datagram := []byte{0x01, 0xAA, 0xBB}
	_, err := stripContextID(datagram)
	if err == nil {
		t.Fatal("expected error for context-id=1, got nil")
	}
}

// TestStripContextID_SingleZeroByte verifies that a datagram consisting of
// only the context-id byte (no payload) returns an empty slice without error.
//
// RED: stripContextID panics (not implemented).
func TestStripContextID_SingleZeroByte(t *testing.T) {
	got, err := stripContextID([]byte{0x00})
	if err != nil {
		t.Fatalf("stripContextID: unexpected error for zero-only: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty payload, got %d bytes", len(got))
	}
}

// TestStripContextID_NoAllocs asserts that stripContextID performs zero heap
// allocations — it must be a pure slice re-slice operation.
//
// RED: stripContextID panics (not implemented).
func TestStripContextID_NoAllocs(t *testing.T) {
	datagram := []byte{0x00, 1, 2, 3, 4, 5, 6, 7, 8}

	allocs := testing.AllocsPerRun(200, func() {
		_, _ = stripContextID(datagram)
	})
	if allocs > 0 {
		t.Fatalf("stripContextID allocs = %.0f, want 0 (must be zero-copy slice reslice)", allocs)
	}
}

// TestStripContextID_ResultSharesMemory verifies that the returned slice is a
// sub-slice of the input (no copy), confirming zero-copy semantics.
//
// RED: stripContextID panics (not implemented).
func TestStripContextID_ResultSharesMemory(t *testing.T) {
	datagram := []byte{0x00, 0x11, 0x22, 0x33}
	got, err := stripContextID(datagram)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Mutate the original; the result slice must reflect the change if zero-copy.
	datagram[1] = 0xFF
	if got[0] != 0xFF {
		t.Fatal("stripContextID returned a copy, want a zero-copy sub-slice")
	}
}

// TestStripContextID_ErrorHasMessage verifies the error for non-zero
// context-id carries enough context for logging (not just a bare sentinel).
//
// RED: stripContextID panics (not implemented).
func TestStripContextID_ErrorHasMessage(t *testing.T) {
	_, err := stripContextID([]byte{0x40, 0x01}) // QUIC varint 2-byte encoding of 64
	if err == nil {
		t.Fatal("expected error for context-id ≠ 0")
	}
	if err.Error() == "" {
		t.Fatal("error message must not be empty")
	}
}

// BenchmarkStripContextID documents per-call throughput.
func BenchmarkStripContextID(b *testing.B) {
	datagram := make([]byte, 1+1400)
	datagram[0] = 0x00
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = stripContextID(datagram)
	}
}
