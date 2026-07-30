// Package sensor 는 플랫폼별 관찰 지점을 담는다.
//
// 현재는 자체 점검용 센서 하나뿐이다. Windows ETW 와 macOS eslogger 센서가 여기에 들어온다.
package sensor

import (
	"context"
	"os"
	"time"

	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/event"
)

// SelfTest 는 커널을 건드리지 않고 네 가지 이벤트 타입을 한 벌씩 만들어 낸다.
//
// 센서를 붙이기 전에 스키마와 전송 경로가 서버 끝까지 맞는지 확인하려는 용도다.
// 이게 대시보드까지 올라오면 남은 일은 진짜 이벤트 소스를 끼우는 것뿐이다.
type SelfTest struct {
	Factory  event.Factory
	Interval time.Duration
	// Hasher 가 있으면 에이전트 자신의 실행 파일 해시를 실어 보낸다. nil 이면 비운다.
	Hasher *FileHasher
}

// Name 은 센서 이름이다.
func (s *SelfTest) Name() string { return "selftest" }

// Run 은 Interval 마다 이벤트 한 벌을 내보내고 ctx 가 끝나면 멈춘다.
func (s *SelfTest) Run(ctx context.Context, out chan<- event.Event) error {
	interval := s.Interval
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		if err := s.emit(ctx, out); err != nil {
			return err
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (s *SelfTest) emit(ctx context.Context, out chan<- event.Event) error {
	now := time.Now()

	// pid 와 해시는 지어내지 않고 에이전트 자신의 것을 쓴다. 해시는 실행 파일을 실제로 읽어
	// 구하므로, 값이 대시보드까지 올라오면 해시기가 이 기기에서 실제로 먹힌다는 뜻이 된다.
	// 지어낸 64자를 넣으면 값이 보여도 그건 확인이 아니다.
	//
	// 그래서 경로는 가짜인데 pid 와 해시는 진짜다. 이 이벤트가 관측 결과로 읽히면 안 되는 이유는
	// 나머지 필드도 마찬가지라(203.0.113.1 은 문서용 주소다) 이 센서 전체에 걸린 전제다.
	self := event.ProcessInfo{
		Path:    "/usr/bin/selftest",
		Cmdline: "selftest --process",
		Parent:  "edrdog-agent",
		PID:     os.Getpid(),
		PPID:    os.Getppid(),
		SHA256:  s.selfSHA256(),
	}
	script := self
	script.Path = "/bin/sh"
	script.Cmdline = "sh /tmp/selftest.sh"

	batch := []event.Event{
		s.Factory.Process(now, self),
		s.Factory.Script(now, script),
		s.Factory.Network(now, event.NetworkInfo{
			ProcessPath: "/usr/bin/selftest",
			PID:         os.Getpid(),
			Protocol:    event.ProtocolTCP,
			DestIP:      "203.0.113.1",
			DestPort:    443,
		}),
		s.Factory.File(now, event.FileInfo{
			Path:   "/tmp/edrdog-selftest.txt",
			Action: event.FileActionCreate,
		}),
		s.Factory.DNS(now, event.DNSInfo{
			ProcessPath: "/usr/bin/selftest",
			PID:         os.Getpid(),
			Protocol:    event.ProtocolUDP,
			Domain:      "selftest.example.com",
		}, map[string]any{
			"queryType": "A",
			"answers":   []string{"203.0.113.1"},
		}),
		s.Factory.L7(now, event.L7Info{
			ProcessPath: "/usr/bin/selftest",
			Protocol:    event.ProtocolTCP,
			Domain:      "selftest.example.com",
			DestIP:      "203.0.113.1",
			DestPort:    443,
		}, map[string]any{
			"issuer":     "CN=EDRdog Selftest CA",
			"selfSigned": true,
		}),
	}
	for _, e := range batch {
		select {
		case out <- e:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// selfSHA256 은 에이전트 실행 파일 자신의 해시다. 구하지 못하면 빈 값이다.
// 경로를 알 수 없는 경우(os.Executable 실패)까지 점검을 세울 이유는 없다. 해시 자리만 비면 된다.
func (s *SelfTest) selfSHA256() string {
	path, err := os.Executable()
	if err != nil {
		return ""
	}
	return s.Hasher.Hash(path)
}
