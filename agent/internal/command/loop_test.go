package command

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/transport"
)

type fakeClient struct {
	mu        sync.Mutex
	beats     int
	queue     [][]transport.Command
	reported  []transport.CommandResult
	beatErr   error
	reportErr error
}

func (c *fakeClient) Heartbeat(context.Context) (transport.Heartbeat, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.beats++
	if c.beatErr != nil {
		return transport.Heartbeat{}, c.beatErr
	}
	var commands []transport.Command
	if len(c.queue) > 0 {
		commands, c.queue = c.queue[0], c.queue[1:]
	}
	return transport.Heartbeat{Commands: commands}, nil
}

func (c *fakeClient) ReportCommand(_ context.Context, r transport.CommandResult) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reported = append(c.reported, r)
	return c.reportErr
}

func (c *fakeClient) results() []transport.CommandResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]transport.CommandResult(nil), c.reported...)
}

type fakeKiller struct {
	mu      sync.Mutex
	targets []string
	status  string
}

func (k *fakeKiller) Kill(target string) (string, string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.targets = append(k.targets, target)
	status := k.status
	if status == "" {
		status = transport.StatusKilled
	}
	return status, "테스트"
}

func (k *fakeKiller) calls() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]string(nil), k.targets...)
}

func newLoop(c *fakeClient, k *fakeKiller) *Loop {
	return New(c, k, Options{Interval: time.Hour})
}

func TestPollExecutesKillAndReports(t *testing.T) {
	c := &fakeClient{queue: [][]transport.Command{{
		{ID: "c1", Type: transport.CommandKillProcess, Target: "/tmp/evil.sh"},
	}}}
	k := &fakeKiller{}

	if err := newLoop(c, k).poll(context.Background()); err != nil {
		t.Fatalf("poll: %v", err)
	}

	if got := k.calls(); len(got) != 1 || got[0] != "/tmp/evil.sh" {
		t.Fatalf("kill 호출 = %v", got)
	}
	results := c.results()
	if len(results) != 1 {
		t.Fatalf("보고 %d 건, want 1", len(results))
	}
	if results[0].CommandID != "c1" || results[0].Status != transport.StatusKilled {
		t.Errorf("보고 내용 = %+v", results[0])
	}
}

func TestSameCommandRunsOnlyOnce(t *testing.T) {
	// 결과 보고가 유실되면 서버가 같은 명령을 다시 내려줄 수 있다.
	// 두 번 죽이는 건 무해하지만, 그 사이 같은 이름으로 뜬 정상 프로세스를 죽일 수 있다.
	same := []transport.Command{{ID: "c1", Type: transport.CommandKillProcess, Target: "/tmp/evil.sh"}}
	c := &fakeClient{queue: [][]transport.Command{same, same}}
	k := &fakeKiller{}
	loop := newLoop(c, k)

	for i := 0; i < 2; i++ {
		if err := loop.poll(context.Background()); err != nil {
			t.Fatalf("poll %d: %v", i, err)
		}
	}

	if got := k.calls(); len(got) != 1 {
		t.Errorf("kill 이 %d 회 호출됐다, want 1", len(got))
	}
	// 다시 받았을 때도 결과는 또 보고해야 한다. 서버가 아직 결과를 못 받았다는 뜻이기 때문이다.
	if got := len(c.results()); got != 2 {
		t.Errorf("보고 %d 건, want 2", got)
	}
}

func TestUnknownCommandTypeIsReportedFailed(t *testing.T) {
	// 모르는 명령을 조용히 무시하면 서버는 영원히 결과를 기다린다.
	c := &fakeClient{queue: [][]transport.Command{{
		{ID: "c1", Type: "reboot_everything", Target: "x"},
	}}}
	k := &fakeKiller{}

	if err := newLoop(c, k).poll(context.Background()); err != nil {
		t.Fatalf("poll: %v", err)
	}

	if len(k.calls()) != 0 {
		t.Error("모르는 명령인데 kill 이 불렸다")
	}
	results := c.results()
	if len(results) != 1 || results[0].Status != transport.StatusFailed {
		t.Fatalf("보고 = %+v", results)
	}
}

func TestKillerStatusIsPassedThrough(t *testing.T) {
	c := &fakeClient{queue: [][]transport.Command{{
		{ID: "c1", Type: transport.CommandKillProcess, Target: "ghost"},
	}}}
	k := &fakeKiller{status: transport.StatusNoMatch}

	if err := newLoop(c, k).poll(context.Background()); err != nil {
		t.Fatalf("poll: %v", err)
	}

	if got := c.results()[0].Status; got != transport.StatusNoMatch {
		t.Errorf("status = %q, want %q", got, transport.StatusNoMatch)
	}
}

func TestExecuteHandlesCommandsFetchedElsewhere(t *testing.T) {
	// 기동할 때 수집 설정을 받으려고 하트비트를 한 번 부르는데, 그 응답에도 명령이 실려 온다.
	// 서버는 한 번 내준 명령을 다시 주지 않으므로, 그걸 버리면 조치가 영영 실행되지 않고
	// 서버는 결과를 기다리다 TIMEOUT 으로 끝난다. 그래서 밖에서 받은 명령도 여기로 넘길 수 있어야 한다.
	c := &fakeClient{}
	k := &fakeKiller{}
	loop := newLoop(c, k)

	loop.Execute(context.Background(), []transport.Command{
		{ID: "c1", Type: transport.CommandKillProcess, Target: "/tmp/evil.sh"},
	})

	if got := k.calls(); len(got) != 1 || got[0] != "/tmp/evil.sh" {
		t.Fatalf("kill 호출 = %v", got)
	}
	if got := c.results(); len(got) != 1 || got[0].CommandID != "c1" {
		t.Fatalf("보고 = %+v", got)
	}
}

func TestExecuteAndPollShareDeduplication(t *testing.T) {
	// 기동 하트비트로 실행한 명령이 다음 폴링에서 또 오면 두 번 죽이면 안 된다.
	same := []transport.Command{{ID: "c1", Type: transport.CommandKillProcess, Target: "/tmp/evil.sh"}}
	c := &fakeClient{queue: [][]transport.Command{same}}
	k := &fakeKiller{}
	loop := newLoop(c, k)

	loop.Execute(context.Background(), same)
	if err := loop.poll(context.Background()); err != nil {
		t.Fatalf("poll: %v", err)
	}

	if got := k.calls(); len(got) != 1 {
		t.Errorf("kill 이 %d 회 호출됐다, want 1", len(got))
	}
}

func TestHeartbeatErrorIsReturned(t *testing.T) {
	c := &fakeClient{beatErr: errors.New("서버 다운")}

	if err := newLoop(c, &fakeKiller{}).poll(context.Background()); err == nil {
		t.Fatal("하트비트 실패인데 err 가 nil 이다")
	}
}

func TestRunStopsOnContextCancel(t *testing.T) {
	c := &fakeClient{}
	loop := New(c, &fakeKiller{}, Options{Interval: time.Millisecond})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- loop.Run(ctx) }()

	// 최소 한 번은 돌아야 한다.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		beats := c.beats
		c.mu.Unlock()
		if beats > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("취소 후에도 안 멈췄다")
	}
}

func TestRunKeepsGoingAfterHeartbeatFailure(t *testing.T) {
	// 서버가 잠깐 죽어도 조치 채널이 영구히 닫히면 안 된다.
	c := &fakeClient{beatErr: errors.New("서버 다운")}
	loop := New(c, &fakeKiller{}, Options{Interval: time.Millisecond})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := loop.Run(ctx); err != nil {
		t.Fatalf("Run = %v, want nil", err)
	}

	c.mu.Lock()
	beats := c.beats
	c.mu.Unlock()
	if beats < 2 {
		t.Errorf("하트비트 %d 회, 실패해도 계속 시도해야 한다", beats)
	}
}
