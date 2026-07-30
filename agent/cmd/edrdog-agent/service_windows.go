//go:build windows

package main

import (
	"context"
	"fmt"
	"log/slog"

	"golang.org/x/sys/windows/svc"
)

// serviceName 은 설치 스크립트가 등록하는 서비스 이름과 같아야 한다.
const serviceName = "edrdog-agent"

// agentService 는 서비스 제어 관리자(SCM)와 대화하는 껍데기다.
//
// SCM 은 서비스를 띄우고 정해진 시간 안에 Running 보고를 받지 못하면 프로세스를 죽인다.
// 그래서 일반 콘솔 프로그램을 그대로 New-Service 로 등록하면 기동에 실패한다.
type agentService struct {
	opts options
	log  *slog.Logger
}

// Execute 는 SCM 이 부른다. 여기서 에이전트를 띄우고 정지 요청을 기다린다.
func (s *agentService) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown

	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- runAgent(ctx, s.opts, s.log) }()

	status <- svc.Status{State: svc.Running, Accepts: accepted}

	for {
		select {
		case req := <-requests:
			switch req.Cmd {
			case svc.Interrogate:
				status <- req.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				// 남은 이벤트를 흘려보낼 시간을 준다. runAgent 가 끝나면 바로 나간다.
				<-done
				return false, 0
			default:
				s.log.Warn("모르는 서비스 제어 요청", "cmd", req.Cmd)
			}
		case err := <-done:
			// 에이전트가 스스로 멈췄다. 설정이 틀렸거나 서버에 붙지 못한 경우다.
			// 0 이 아닌 코드로 끝내야 SCM 이 실패로 기록하고 복구 정책을 적용한다.
			status <- svc.Status{State: svc.StopPending}
			if err != nil {
				s.log.Error("에이전트가 멈췄다", "err", err)
				return false, 1
			}
			return false, 0
		}
	}
}

// runAsService 는 SCM 아래에서 에이전트를 돌린다.
func runAsService(opts options, log *slog.Logger) error {
	inService, err := svc.IsWindowsService()
	if err != nil {
		return fmt.Errorf("서비스로 실행 중인지 판단하지 못했다: %w", err)
	}
	if !inService {
		return fmt.Errorf("-service 는 서비스로 등록된 상태에서만 쓴다. 직접 실행할 때는 이 플래그를 빼라")
	}
	return svc.Run(serviceName, &agentService{opts: opts, log: log})
}
