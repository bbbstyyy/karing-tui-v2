package core

import "sync"

// RingBuffer is a fixed-capacity io.Writer that retains only the newest bytes.
// It is intended for child-process stdout/stderr so noisy logs cannot grow
// daemon memory without bound.
type RingBuffer struct {
	mu       sync.Mutex
	capacity int
	data     []byte
}

func NewRingBuffer(capacity int) *RingBuffer {
	if capacity < 1 {
		capacity = 1
	}
	return &RingBuffer{capacity: capacity}
}

func (b *RingBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	written := len(p)
	if len(p) >= b.capacity {
		b.data = append(b.data[:0], p[len(p)-b.capacity:]...)
		return written, nil
	}

	overflow := len(b.data) + len(p) - b.capacity
	if overflow > 0 {
		copy(b.data, b.data[overflow:])
		b.data = b.data[:len(b.data)-overflow]
	}
	b.data = append(b.data, p...)
	return written, nil
}

func (b *RingBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()

	result := make([]byte, len(b.data))
	copy(result, b.data)
	return result
}
