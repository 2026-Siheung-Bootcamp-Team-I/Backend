// Package sensor 는 플랫폼별 관찰 지점을 담는다.
//
// 현재는 자체 점검용 센서 하나뿐이다. Windows ETW 와 macOS eslogger 센서가 여기에 들어온다.
package sensor

import (
	"context"
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
	batch := []event.Event{
		s.Factory.Process(now, "/usr/bin/selftest", "selftest --process", "edrdog-agent"),
		s.Factory.Script(now, "/bin/sh", "sh /tmp/selftest.sh", "edrdog-agent"),
		s.Factory.Network(now, "/usr/bin/selftest", "203.0.113.1", 443),
		s.Factory.File(now, "/tmp/edrdog-selftest.txt"),
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
