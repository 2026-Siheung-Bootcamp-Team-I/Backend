package command

import (
	"fmt"
	"strings"
	"syscall"

	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/transport"
)

// 상태 문자열은 transport 의 것을 쓴다. 여기서 짧게 부르려고 별칭을 둔다.
const (
	statusKilled  = transport.StatusKilled
	statusNoMatch = transport.StatusNoMatch
	statusFailed  = transport.StatusFailed
)

// process 는 실행 중인 프로세스 하나다.
type process struct {
	pid  int
	path string
}

// killMatching 은 target 과 일치하는 프로세스를 종료하고 결과를 돌려준다.
//
// 플랫폼별 코드가 프로세스 목록과 실제 종료 함수만 넘겨주면 되도록 분리했다.
// 판단 로직이 여기 모여 있어야 Windows 없이도 검증할 수 있다.
func killMatching(target string, procs []process, caseInsensitive bool, kill func(pid int, sig syscall.Signal) error) (string, string) {
	self := selfPID()

	var killed, failed []string
	for _, p := range procs {
		if !Matches(target, p.path, caseInsensitive) {
			continue
		}
		// 자기 자신을 죽이면 수집이 멈추고 다시 살아날 방법이 없다.
		// PID 1 은 init/launchd 라 죽이면 기기가 망가진다.
		if p.pid == self || p.pid <= 1 {
			continue
		}
		if err := kill(p.pid, syscall.SIGKILL); err != nil {
			failed = append(failed, fmt.Sprintf("%d(%v)", p.pid, err))
			continue
		}
		killed = append(killed, fmt.Sprint(p.pid))
	}

	switch {
	case len(killed) > 0 && len(failed) == 0:
		return statusKilled, fmt.Sprintf("pid %s 종료", strings.Join(killed, " "))
	case len(killed) > 0:
		// 일부만 죽었으면 성공으로 볼 수 없다. 서버가 KILLED 를 받으면 알림을 확인 처리하는데,
		// 대상 프로세스가 아직 살아 있을 수 있다.
		return statusFailed, fmt.Sprintf("일부만 종료했다. 성공 pid %s, 실패 %s",
			strings.Join(killed, " "), strings.Join(failed, " "))
	case len(failed) > 0:
		return statusFailed, fmt.Sprintf("종료 실패 %s", strings.Join(failed, " "))
	default:
		return statusNoMatch, fmt.Sprintf("%q 로 도는 프로세스가 없다", target)
	}
}
