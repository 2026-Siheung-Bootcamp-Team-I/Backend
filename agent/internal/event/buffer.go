package event

import "sync"

// Buffer 는 센서와 전송 사이의 경계 있는 큐다. 용량을 넘으면 가장 오래된 것부터 버린다.
// 경계를 없애면 서버가 죽어 있는 동안 에이전트 메모리가 무한정 늘어난다.
// 모든 메서드는 여러 센서 고루틴에서 동시에 불려도 안전하다.
type Buffer struct {
	mu       sync.Mutex
	items    []Event
	capacity int
	dropped  int
}

// NewBuffer 는 최대 capacity 건을 담는 버퍼를 만든다.
func NewBuffer(capacity int) *Buffer {
	if capacity < 1 {
		capacity = 1
	}
	return &Buffer{items: make([]Event, 0, capacity), capacity: capacity}
}

// Add 는 이벤트 한 건을 넣는다. 가득 차 있으면 가장 오래된 것을 버린다.
func (b *Buffer) Add(e Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.items = append(b.items, e)
	b.trimFrontLocked()
}

// Drain 은 오래된 순으로 최대 max 건을 꺼내 버퍼에서 지운다.
func (b *Buffer) Drain(max int) []Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	if max > len(b.items) {
		max = len(b.items)
	}
	if max < 1 {
		return nil
	}
	batch := make([]Event, max)
	copy(batch, b.items[:max])
	b.items = append(b.items[:0], b.items[max:]...)
	return batch
}

// Requeue 는 전송에 실패한 배치를 순서를 지켜 맨 앞으로 되돌린다.
// 되돌린 뒤에도 용량은 넘지 않으며, 넘치는 만큼은 앞에서부터 버린다.
func (b *Buffer) Requeue(batch []Event) {
	if len(batch) == 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.items = append(append(make([]Event, 0, len(batch)+len(b.items)), batch...), b.items...)
	b.trimFrontLocked()
}

// Len 은 현재 쌓여 있는 건수다.
func (b *Buffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.items)
}

// Dropped 는 용량 초과로 버린 누적 건수다. 상태 보고에 쓴다.
func (b *Buffer) Dropped() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.dropped
}

func (b *Buffer) trimFrontLocked() {
	if overflow := len(b.items) - b.capacity; overflow > 0 {
		b.items = append(b.items[:0], b.items[overflow:]...)
		b.dropped += overflow
	}
}
