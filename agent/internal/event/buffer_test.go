package event

import (
	"sync"
	"testing"
)

func evt(name string) Event {
	return Event{Type: TypeProcess, Process: name}
}

func paths(events []Event) []string {
	out := make([]string, len(events))
	for i, e := range events {
		out[i] = e.Process
	}
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestDrainReturnsOldestFirst(t *testing.T) {
	b := NewBuffer(10)
	b.Add(evt("a"))
	b.Add(evt("b"))
	b.Add(evt("c"))

	got := paths(b.Drain(10))
	if !equal(got, []string{"a", "b", "c"}) {
		t.Errorf("Drain = %v, want [a b c]", got)
	}
	if b.Len() != 0 {
		t.Errorf("Drain 후 Len = %d, want 0", b.Len())
	}
}

func TestDrainRespectsBatchSize(t *testing.T) {
	b := NewBuffer(10)
	for _, p := range []string{"a", "b", "c"} {
		b.Add(evt(p))
	}

	if got := paths(b.Drain(2)); !equal(got, []string{"a", "b"}) {
		t.Errorf("Drain(2) = %v, want [a b]", got)
	}
	if got := paths(b.Drain(2)); !equal(got, []string{"c"}) {
		t.Errorf("남은 Drain = %v, want [c]", got)
	}
}

func TestAddDropsOldestWhenFull(t *testing.T) {
	// 서버가 죽어 있어도 에이전트 메모리는 늘지 않아야 한다.
	// 오래된 이벤트를 버리는 이유는 최신 행위가 탐지에 더 쓸모 있기 때문이다.
	b := NewBuffer(2)
	b.Add(evt("a"))
	b.Add(evt("b"))
	b.Add(evt("c"))

	if got := paths(b.Drain(10)); !equal(got, []string{"b", "c"}) {
		t.Errorf("Drain = %v, want [b c]", got)
	}
	if b.Dropped() != 1 {
		t.Errorf("Dropped = %d, want 1", b.Dropped())
	}
}

func TestRequeuePutsBatchBackInFront(t *testing.T) {
	// 전송에 실패한 배치는 순서를 지키려고 앞으로 되돌린다.
	b := NewBuffer(10)
	b.Add(evt("a"))
	b.Add(evt("b"))
	failed := b.Drain(1)
	b.Add(evt("c"))

	b.Requeue(failed)

	if got := paths(b.Drain(10)); !equal(got, []string{"a", "b", "c"}) {
		t.Errorf("Drain = %v, want [a b c]", got)
	}
}

func TestRequeueDropsOverflowFromFront(t *testing.T) {
	// 되돌릴 자리가 모자라면 가장 오래된 것부터 버린다. 용량은 절대 넘지 않는다.
	b := NewBuffer(2)
	b.Add(evt("c"))
	b.Add(evt("d"))

	b.Requeue([]Event{evt("a"), evt("b")})

	if b.Len() != 2 {
		t.Fatalf("Len = %d, want 2", b.Len())
	}
	if got := paths(b.Drain(10)); !equal(got, []string{"c", "d"}) {
		t.Errorf("Drain = %v, want [c d]", got)
	}
	if b.Dropped() != 2 {
		t.Errorf("Dropped = %d, want 2", b.Dropped())
	}
}

func TestBufferIsSafeForConcurrentSensors(t *testing.T) {
	// 센서마다 고루틴이 하나씩 붙으므로 Add 는 동시 호출된다.
	b := NewBuffer(1000)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				b.Add(evt("x"))
			}
		}()
	}
	wg.Wait()

	if b.Len() != 1000 {
		t.Errorf("Len = %d, want 1000", b.Len())
	}
}
