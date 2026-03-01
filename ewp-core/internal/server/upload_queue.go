package server

import (
	"container/heap"
	"io"
	"sync"
	"sync/atomic"
)

type Packet struct {
	Payload []byte
	Seq     uint64
}

// UploadQueue is a concurrent-safe, heap-based, in-order packet queue.
//
// It serves xHTTP multi-segment uploads where individual POST requests may
// arrive out of order. Packets are reordered by Seq and delivered to Read()
// strictly in-order, blocking until the next expected packet arrives.
//
// writeSeq (atomic) is the producer-side sequence counter: callers use
// NextSeq() to obtain monotonically-increasing values for streaming uploads.
// readSeq (mutex-protected, inside Read()) tracks the next expected Seq for
// the consumer.  The two counters are intentionally separate so that multiple
// concurrent producer goroutines can call NextSeq() without conflicting with
// the consumer's Read() progress.
type UploadQueue struct {
	mu         sync.Mutex
	cond       *sync.Cond
	h          uploadHeap
	readSeq    uint64
	writeSeq   atomic.Uint64
	closed     bool
	maxPackets int
}

func NewUploadQueue(maxPackets int) *UploadQueue {
	q := &UploadQueue{maxPackets: maxPackets}
	q.cond = sync.NewCond(&q.mu)
	return q
}

// NextSeq atomically assigns the next sequence number for a streaming upload
// chunk. Lock-free on the hot path via atomic add.
func (q *UploadQueue) NextSeq() uint64 {
	return q.writeSeq.Add(1) - 1
}

// Push enqueues a packet. Returns io.ErrClosedPipe if the queue is closed,
// io.ErrShortBuffer if the heap is full.
func (q *UploadQueue) Push(p Packet) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.closed {
		return io.ErrClosedPipe
	}
	if len(q.h) >= q.maxPackets {
		return io.ErrShortBuffer
	}
	heap.Push(&q.h, p)
	q.cond.Signal()
	return nil
}

// Close signals EOF to the consumer. Safe to call multiple times.
func (q *UploadQueue) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.closed {
		q.closed = true
		q.cond.Broadcast()
	}
	return nil
}

// Read blocks until the next in-order packet is available, then copies its
// payload into b. Supports partial reads: if b is smaller than the payload,
// the remainder is pushed back with the same Seq for the next Read call.
// Returns io.EOF when the queue is closed and drained.
func (q *UploadQueue) Read(b []byte) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	for {
		if len(q.h) > 0 && q.h[0].Seq == q.readSeq {
			pkt := heap.Pop(&q.h).(Packet)
			n := copy(b, pkt.Payload)
			if n < len(pkt.Payload) {
				heap.Push(&q.h, Packet{Payload: pkt.Payload[n:], Seq: q.readSeq})
			} else {
				q.readSeq++
			}
			return n, nil
		}

		if q.closed {
			return 0, io.EOF
		}

		if len(q.h) >= q.maxPackets {
			return 0, io.ErrShortBuffer
		}

		q.cond.Wait()
	}
}

type uploadHeap []Packet

func (h uploadHeap) Len() int           { return len(h) }
func (h uploadHeap) Less(i, j int) bool { return h[i].Seq < h[j].Seq }
func (h uploadHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *uploadHeap) Push(x any) { *h = append(*h, x.(Packet)) }

func (h *uploadHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}
