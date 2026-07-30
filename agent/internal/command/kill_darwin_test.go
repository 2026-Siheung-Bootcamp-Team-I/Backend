//go:build darwin

package command

import (
	"os"
	"testing"

	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/transport"
)

func TestListProcessesFindsSelf(t *testing.T) {
	// libproc 배선이 실제로 도는지 확인한다. 자기 자신은 반드시 목록에 있어야 한다.
	procs, err := listProcesses()
	if err != nil {
		t.Fatalf("listProcesses: %v", err)
	}
	if len(procs) < 2 {
		t.Fatalf("프로세스가 %d 개뿐이다. 열거가 안 되고 있다", len(procs))
	}

	self := os.Getpid()
	for _, p := range procs {
		if p.pid == self {
			if p.path == "" {
				t.Error("자기 자신의 실행 경로가 비었다")
			}
			return
		}
	}
	t.Errorf("자기 자신(pid %d)이 목록에 없다", self)
}

func TestKillReportsNoMatchForUnknownTarget(t *testing.T) {
	// 실제 종료까지 가지 않는 경로로 Kill 전체를 한 번 돌려본다.
	status, message := NewKiller().Kill("edrdog-이런-프로세스는-없다")

	if status != transport.StatusNoMatch {
		t.Errorf("status = %q (%s), want %q", status, message, transport.StatusNoMatch)
	}
}
