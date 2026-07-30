package runtime

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/event"
)

type fakeSender struct {
	mu    sync.Mutex
	sent  [][]event.Event
	fails int
}

func (s *fakeSender) SendEvents(_ context.Context, events []event.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	batch := make([]event.Event, len(events))
	copy(batch, events)
	s.sent = append(s.sent, batch)
	if s.fails > 0 {
		s.fails--
		return errors.New("서버 다운")
	}
	return nil
}

func (s *fakeSender) batches() [][]event.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sent
}

func evt(name string) event.Event {
	return event.Event{Type: event.TypeProcess, Process: name}
}

func TestFlushSendsBufferedEvents(t *testing.T) {
	sender := &fakeSender{}
	r := New(sender, Options{BatchSize: 10})
	r.Buffer().Add(evt("a"))
	r.Buffer().Add(evt("b"))

	if err := r.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	if got := len(sender.batches()); got != 1 {
		t.Fatalf("전송 %d 회, want 1", got)
	}
	if got := len(sender.batches()[0]); got != 2 {
		t.Errorf("배치 크기 %d, want 2", got)
	}
	if r.Buffer().Len() != 0 {
		t.Errorf("성공 후 버퍼에 %d 건 남았다", r.Buffer().Len())
	}
}

func TestFlushRequeuesOnFailure(t *testing.T) {
	// 전송이 실패했는데 배치를 버리면 그 이벤트는 영영 사라진다.
	sender := &fakeSender{fails: 1}
	r := New(sender, Options{BatchSize: 10})
	r.Buffer().Add(evt("a"))

	if err := r.Flush(context.Background()); err == nil {
		t.Fatal("전송 실패인데 err 가 nil 이다")
	}
	if r.Buffer().Len() != 1 {
		t.Fatalf("되돌린 뒤 버퍼 %d 건, want 1", r.Buffer().Len())
	}

	// 다음 시도에서 같은 이벤트가 다시 나가야 한다.
	if err := r.Flush(context.Background()); err != nil {
		t.Fatalf("두 번째 Flush: %v", err)
	}
	if got := sender.batches()[1][0].Process; got != "a" {
		t.Errorf("재전송 process = %q, want a", got)
	}
}

func TestFlushSendsNothingWhenEmpty(t *testing.T) {
	sender := &fakeSender{}
	r := New(sender, Options{BatchSize: 10})

	if err := r.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got := len(sender.batches()); got != 0 {
		t.Errorf("빈 버퍼로 %d 회 전송, want 0", got)
	}
}

func TestFlushLimitsBatchSize(t *testing.T) {
	// 한 번에 다 보내면 서버가 죽었다 살아난 직후 거대한 요청이 날아간다.
	sender := &fakeSender{}
	r := New(sender, Options{BatchSize: 2})
	for _, p := range []string{"a", "b", "c"} {
		r.Buffer().Add(evt(p))
	}

	if err := r.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got := len(sender.batches()[0]); got != 2 {
		t.Errorf("배치 크기 %d, want 2", got)
	}
	if r.Buffer().Len() != 1 {
		t.Errorf("남은 버퍼 %d 건, want 1", r.Buffer().Len())
	}
}

type fakeSensor struct {
	name  string
	emit  int
	ended chan struct{}
}

func (s *fakeSensor) Name() string { return s.name }

func (s *fakeSensor) Run(ctx context.Context, out chan<- event.Event) error {
	defer close(s.ended)
	for i := 0; i < s.emit; i++ {
		select {
		case out <- evt(s.name):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	<-ctx.Done()
	return ctx.Err()
}

func TestRunCollectsFromSensorsAndFlushesOnStop(t *testing.T) {
	sender := &fakeSender{}
	r := New(sender, Options{BatchSize: 10, FlushInterval: time.Hour})
	sensor := &fakeSensor{name: "fake", emit: 3, ended: make(chan struct{})}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx, []Sensor{sensor}) }()

	// 센서가 낸 이벤트가 버퍼에 들어올 때까지 기다린다.
	waitFor(t, func() bool { return r.Buffer().Len() == 3 })

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}

	// 종료할 때 남은 이벤트를 흘려보내지 않으면 마지막 배치를 잃는다.
	if got := len(sender.batches()); got != 1 {
		t.Fatalf("종료 시 전송 %d 회, want 1", got)
	}
	if got := len(sender.batches()[0]); got != 3 {
		t.Errorf("마지막 배치 %d 건, want 3", got)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("조건이 시간 안에 만족되지 않았다")
}
