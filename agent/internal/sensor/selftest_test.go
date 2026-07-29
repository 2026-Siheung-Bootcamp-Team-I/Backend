package sensor

import (
	"context"
	"testing"
	"time"

	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/event"
)

func TestSelfTestEmitsEveryEventType(t *testing.T) {
	s := &SelfTest{Factory: event.Factory{Host: "lab"}, Interval: time.Hour}
	out := make(chan event.Event, 16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.Run(ctx, out)
	}()

	seen := map[string]bool{}
	for i := 0; i < 4; i++ {
		select {
		case e := <-out:
			seen[e.Type] = true
			if e.Host != "lab" {
				t.Errorf("host = %q, want lab", e.Host)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("이벤트를 %d 개만 받았다", i)
		}
	}
	cancel()
	<-done

	for _, eventType := range []string{event.TypeProcess, event.TypeScript, event.TypeNetwork, event.TypeFile} {
		if !seen[eventType] {
			t.Errorf("%s 이벤트가 안 나왔다", eventType)
		}
	}
}

func TestSelfTestStopsOnContextCancel(t *testing.T) {
	s := &SelfTest{Factory: event.Factory{Host: "lab"}, Interval: time.Millisecond}
	// 아무도 읽지 않는 채널이라 첫 전송에서 막힌다. 그래도 취소로 빠져나와야 한다.
	out := make(chan event.Event)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, out) }()
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Error("취소로 끝났는데 err 가 nil 이다")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("취소 후에도 안 멈췄다")
	}
}
