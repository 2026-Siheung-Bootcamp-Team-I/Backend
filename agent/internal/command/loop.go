package command

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/transport"
)

// Client 는 서버와의 명령 왕복이다. transport.Client 가 이걸 만족한다.
type Client interface {
	Heartbeat(ctx context.Context) (transport.Heartbeat, error)
	ReportCommand(ctx context.Context, result transport.CommandResult) error
}

// Killer 는 실제로 프로세스를 종료한다. 플랫폼마다 구현이 다르다.
// 반환은 (상태, 사람이 읽을 메시지)이고 상태는 transport.Status* 중 하나다.
type Killer interface {
	Kill(target string) (status string, message string)
}

// Options 는 루프 동작을 조절한다.
type Options struct {
	Interval time.Duration
	Logger   *slog.Logger
}

// Loop 는 하트비트로 명령을 받아 실행하고 결과를 보고한다. 엔드포인트가 방화벽 안쪽이라 에이전트가 먼저 물어본다.
type Loop struct {
	client   Client
	killer   Killer
	interval time.Duration
	log      *slog.Logger

	// done 은 이미 실행한 명령의 결과다. 다시 내려온 명령을 재실행하면 그 사이 같은 이름으로 뜬 정상 프로세스를 죽인다.
	done map[string]transport.CommandResult
}

// doneLimit 은 기억할 명령 수 상한이다. 오래 도는 에이전트에서 맵이 무한정 커지는 것만 막는다.
const doneLimit = 256

// New 는 명령 루프를 만든다.
func New(client Client, killer Killer, opts Options) *Loop {
	// 이 주기가 곧 하트비트 주기다. 늘리면 조치가 그만큼 늦게 나가고 서버가 보는 마지막 접속 시각도 늦어진다.
	if opts.Interval <= 0 {
		opts.Interval = 3 * time.Second
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Loop{
		client:   client,
		killer:   killer,
		interval: opts.Interval,
		log:      opts.Logger,
		done:     make(map[string]transport.CommandResult),
	}
}

// Run 은 주기마다 서버에 명령을 물어보고 실행한다. ctx 가 끝나면 nil 을 돌려준다.
// 하트비트가 실패해도 루프를 끝내지 않는다. 서버가 잠깐 죽었다고 조치 채널이 영구히 닫히면 안 된다.
func (l *Loop) Run(ctx context.Context) error {
	ticker := time.NewTicker(l.interval)
	defer ticker.Stop()

	for {
		if err := l.poll(ctx); err != nil && ctx.Err() == nil {
			l.log.Warn("명령 확인 실패, 다음 주기에 재시도", "err", err)
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return nil
		}
	}
}

// poll 은 한 주기를 처리한다. 하트비트로 명령을 받아 실행하고 결과를 보고한다.
func (l *Loop) poll(ctx context.Context) error {
	beat, err := l.client.Heartbeat(ctx)
	if err != nil {
		return err
	}
	l.Execute(ctx, beat.Commands)
	return nil
}

// Execute 는 명령 묶음을 실행하고 결과를 보고한다. 기동 시 첫 하트비트에 실려 온 명령도 처리하려고 열어 뒀다.
func (l *Loop) Execute(ctx context.Context, commands []transport.Command) {
	for _, cmd := range commands {
		result := l.run(cmd)
		// 이미 실행했던 명령도 결과는 다시 보고한다. 서버가 아직 결과를 못 받았다는 뜻이기 때문이다.
		if err := l.client.ReportCommand(ctx, result); err != nil {
			l.log.Warn("명령 결과 보고 실패", "command", cmd.ID, "err", err)
		}
	}
}

// run 은 명령 하나를 실행하고 결과를 돌려준다. 이미 실행한 명령이면 저장된 결과를 쓴다.
func (l *Loop) run(cmd transport.Command) transport.CommandResult {
	if prev, already := l.done[cmd.ID]; already {
		return prev
	}

	var result transport.CommandResult
	switch cmd.Type {
	case transport.CommandKillProcess:
		status, message := l.killer.Kill(cmd.Target)
		result = transport.CommandResult{CommandID: cmd.ID, Status: status, Message: message}
	default:
		// 조용히 무시하면 서버가 결과를 기다리다 TIMEOUT 으로 끝나므로 실패를 명시한다.
		result = transport.CommandResult{
			CommandID: cmd.ID,
			Status:    transport.StatusFailed,
			Message:   fmt.Sprintf("모르는 명령 종류: %s", cmd.Type),
		}
	}

	l.remember(cmd.ID, result)
	return result
}

func (l *Loop) remember(id string, result transport.CommandResult) {
	if len(l.done) >= doneLimit {
		l.done = make(map[string]transport.CommandResult)
	}
	l.done[id] = result
}
