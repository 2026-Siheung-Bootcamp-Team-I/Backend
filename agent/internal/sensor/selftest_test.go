package sensor

import (
	"context"
	"encoding/json"
	"os"
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
	for i := 0; i < 6; i++ {
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

	for _, eventType := range []string{event.TypeProcess, event.TypeScript, event.TypeNetwork, event.TypeFile, event.TypeDNS, event.TypeL7} {
		if !seen[eventType] {
			t.Errorf("%s 이벤트가 안 나왔다", eventType)
		}
	}
}

// 자체 점검은 스키마와 전송 경로가 서버 끝까지 맞는지 보는 용도다. 새로 생긴 필드가 비어
// 있으면 그 경로는 점검되지 않는다. 값은 지어내지 않고 에이전트 자신의 것을 쓴다.
func TestSelfTestFillsIdentifiersAndHash(t *testing.T) {
	s := &SelfTest{Factory: event.Factory{Host: "lab"}, Interval: time.Hour, Hasher: NewFileHasher()}
	out := make(chan event.Event, 16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := s.emit(ctx, out); err != nil {
		t.Fatalf("emit: %v", err)
	}
	close(out)

	byType := map[string]event.Event{}
	for e := range out {
		byType[e.Type] = e
	}

	// 테스트 바이너리 자신의 해시라 값을 미리 알 수는 없다. 채워졌는지와 모양만 본다.
	if sum := byType[event.TypeProcess].SHA256; len(sum) != 64 {
		t.Errorf("process.sha256 = %q, want 64자 16진수", sum)
	}
	if got := byType[event.TypeFile].SHA256; got != "" {
		t.Errorf("file.sha256 = %q, 파일 이벤트에는 붙이지 않는다", got)
	}

	pid := float64(os.Getpid())
	cases := map[string]map[string]any{
		event.TypeProcess: {"pid": pid, "ppid": float64(os.Getppid())},
		event.TypeScript:  {"pid": pid, "ppid": float64(os.Getppid())},
		event.TypeNetwork: {"pid": pid, "protocol": "tcp"},
		event.TypeFile:    {"action": "CREATE"},
		event.TypeDNS:     {"pid": pid, "protocol": "udp"},
		event.TypeL7:      {"protocol": "tcp"},
	}
	for eventType, want := range cases {
		detail := map[string]any{}
		if raw := byType[eventType].Detail; raw != "" {
			if err := json.Unmarshal([]byte(raw), &detail); err != nil {
				t.Fatalf("%s 의 detail 이 JSON 이 아니다: %v", eventType, err)
			}
		}
		for key, value := range want {
			if detail[key] != value {
				t.Errorf("%s detail.%s = %v, want %v", eventType, key, detail[key], value)
			}
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
