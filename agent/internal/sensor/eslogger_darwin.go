//go:build darwin

package sensor

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"strings"
	"time"

	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/event"
)

// eslDefaultPath 는 macOS 13 부터 기본 탑재된 eslogger 위치다.
const eslDefaultPath = "/usr/bin/eslogger"

// eslEventTypes 는 구독할 이벤트다. eslogger 는 소문자 짧은 이름을 위치 인자로 받는다.
var eslEventTypes = []string{"exec", "create", "rename", "unlink"}

const (
	// eslMaxLineBytes 는 한 줄의 상한이다.
	// exec 이벤트는 인자와 파일 서술자 목록까지 담아 수백 KB 가 되기도 한다.
	// bufio.Scanner 의 기본 상한 64KB 로는 그런 줄이 통째로 잘려 파싱이 실패한다.
	eslMaxLineBytes = 4 << 20

	// 재기동 간격. 상한을 두지 않으면 eslogger 가 계속 죽을 때 간격이 무한정 늘어난다.
	eslMinBackoff = time.Second
	eslMaxBackoff = time.Minute

	// eslStderrKeep 은 오류 메시지에 붙일 stderr 마지막 줄 수다.
	eslStderrKeep = 5

	// eslHashHealthInterval 은 해시 집계를 로그로 남기는 주기다.
	// ETW 센서의 etwHealthInterval 과 같은 값으로 맞춰 두 플랫폼의 로그가 같은 리듬으로 나오게 한다.
	eslHashHealthInterval = time.Minute
)

// ESLoggerSensor 는 /usr/bin/eslogger 를 자식 프로세스로 띄워 EndpointSecurity 이벤트를 읽는다.
//
// EndpointSecurity API 를 직접 쓰려면 Apple 의 entitlement 심사를 통과해야 한다. eslogger 는
// 그 entitlement 를 이미 가진 애플 서명 바이너리라 심사 없이 같은 이벤트를 받을 수 있다.
// 대신 root 권한과 전체 디스크 접근 권한이 필요하다.
type ESLoggerSensor struct {
	Factory    event.Factory
	WatchPaths []string
	// ESLoggerPath 가 비면 /usr/bin/eslogger 를 쓴다.
	ESLoggerPath string
	// Logger 가 비면 slog.Default() 를 쓴다.
	Logger *slog.Logger
	// Hasher 가 있으면 exec 이벤트에 실행 이미지의 sha256 을 붙인다. nil 이면 붙이지 않는다.
	Hasher *FileHasher
}

// Name 은 센서 이름이다.
func (s *ESLoggerSensor) Name() string { return "eslogger" }

// Run 은 eslogger 를 띄우고 출력을 이벤트로 바꿔 내보낸다. ctx 가 끝나면 멈춘다.
//
// eslogger 가 죽으면 백오프를 두고 다시 띄운다. 다만 한 줄도 읽지 못한 채 끝났다면
// 재시도하지 않고 오류를 올린다. 원인이 환경에 있는데(바이너리 없음, root 아님,
// 전체 디스크 접근 권한 없음) 조용히 재시도만 하면 이벤트 0건의 이유를 찾을 수 없다.
func (s *ESLoggerSensor) Run(ctx context.Context, out chan<- event.Event) error {
	binPath := s.ESLoggerPath
	if binPath == "" {
		binPath = eslDefaultPath
	}
	watch := ExpandWatchPaths(s.WatchPaths)
	log := s.logger()
	log.Info("eslogger 센서 시작", "path", binPath, "events", eslEventTypes, "watchPaths", watch)

	// 해시 집계를 주기적으로 남긴다. 해시가 전부 비어 있을 때 그 원인이 권한 부족인지 크기
	// 상한인지 로그만 보고 가릴 수 있어야 한다. ctx 가 끝나면 같이 멈춘다.
	if s.Hasher != nil {
		go s.reportHashHealth(ctx)
	}

	backoff := eslMinBackoff
	healthy := false

	for {
		lines, err := s.runOnce(ctx, binPath, watch, out)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if lines > 0 {
			healthy = true
			backoff = eslMinBackoff
		}
		if err == nil {
			err = errors.New("eslogger 가 스스로 종료했다")
		}
		if !healthy {
			return fmt.Errorf("eslogger 에서 한 줄도 읽지 못했다 (%s, root 와 전체 디스크 접근 권한이 필요하다): %w", binPath, err)
		}

		log.Warn("eslogger 가 멈췄다, 다시 띄운다", "err", err, "backoff", backoff)
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return ctx.Err()
		}
		backoff *= 2
		if backoff > eslMaxBackoff {
			backoff = eslMaxBackoff
		}
	}
}

// runOnce 는 eslogger 를 한 번 띄워 끝날 때까지 읽는다. 읽은 줄 수와 끝난 이유를 돌려준다.
func (s *ESLoggerSensor) runOnce(ctx context.Context, binPath string, watch []string, out chan<- event.Event) (int, error) {
	args := append([]string{"--format", "json"}, eslEventTypes...)
	cmd := exec.CommandContext(ctx, binPath, args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return 0, err
	}
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("실행할 수 없다: %w", err)
	}

	// ctx 가 끝나면 파이프를 직접 닫는다.
	// CommandContext 는 eslogger 만 죽이는데, 파이프를 물려받은 자식이 남아 있으면
	// 읽기가 끝나지 않아 센서가 종료하지 못한다.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = stdout.Close()
			_ = stderr.Close()
		case <-stop:
		}
	}()

	// stderr 를 따로 읽는다. 기동 실패 원인은 stdout 이 아니라 여기에만 나온다.
	var tail eslStderr
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		tail.drain(stderr, s.logger())
	}()

	lines, readErr := s.pump(ctx, stdout, watch, out)
	<-drained
	waitErr := cmd.Wait()

	err = readErr
	if err == nil {
		err = waitErr
	}
	if msg := tail.String(); err != nil && msg != "" {
		err = fmt.Errorf("%w (stderr: %s)", err, msg)
	}
	return lines, err
}

// pump 은 stdout 을 줄 단위로 읽어 이벤트로 바꿔 내보낸다.
func (s *ESLoggerSensor) pump(ctx context.Context, stdout io.Reader, watch []string, out chan<- event.Event) (int, error) {
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), eslMaxLineBytes)

	lines := 0
	for scanner.Scan() {
		lines++
		e, ok := MapLine(s.Factory, scanner.Bytes(), watch, s.Hasher)
		if !ok {
			continue
		}
		select {
		case out <- e:
		case <-ctx.Done():
			return lines, ctx.Err()
		}
	}
	return lines, scanner.Err()
}

// reportHashHealth 는 해시 집계를 주기마다 로그로 남긴다.
func (s *ESLoggerSensor) reportHashHealth(ctx context.Context) {
	ticker := time.NewTicker(eslHashHealthInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h := s.Hasher.Stats()
			s.logger().Info("실행 파일 해시 상태",
				"hashed", h.Hashed, "cached", h.Cached, "failed", h.Failed, "tooBig", h.TooBig)
		}
	}
}

func (s *ESLoggerSensor) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

// eslStderr 는 eslogger 의 stderr 를 로그로 넘기면서 마지막 몇 줄을 남긴다.
// 남긴 줄은 센서가 올리는 오류 메시지에 붙는다.
type eslStderr struct {
	lines []string
}

// drain 은 r 이 끝날 때까지 읽는다. 읽기를 마친 뒤에만 String 을 부를 수 있다.
func (t *eslStderr) drain(r io.Reader, log *slog.Logger) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 4096), eslMaxLineBytes)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		log.Warn("eslogger stderr", "line", line)
		t.lines = append(t.lines, line)
		if len(t.lines) > eslStderrKeep {
			t.lines = t.lines[1:]
		}
	}
}

func (t *eslStderr) String() string {
	return strings.Join(t.lines, " | ")
}
