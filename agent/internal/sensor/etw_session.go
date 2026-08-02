package sensor

import (
	"errors"
	"syscall"
)

// ETW 세션 생성 실패를 사람이 조치할 수 있는 문구로 바꾼다.
// etw_windows.go 가 쓰지만 여기 두어야 Windows 기기 없이도 테스트가 돈다.

// ETW 세션 생성이 실패하는 대표적인 두 가지 Windows 오류 코드. 조치가 정반대라 갈라 준다.
const (
	winErrorAccessDenied  = 5   // ERROR_ACCESS_DENIED
	winErrorAlreadyExists = 183 // ERROR_ALREADY_EXISTS
)

// sessionErrorHint 는 세션 생성 실패 원인에 맞는 조치를 한 줄로 돌려준다.
func sessionErrorHint(err error, sessionName string) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch uintptr(errno) {
		case winErrorAlreadyExists:
			return "같은 이름의 세션이 이미 돌고 있다. logman stop " + sessionName + " -ets 로 지워라"
		case winErrorAccessDenied:
			return "권한이 없다. 관리자 권한으로 실행하거나 Performance Log Users 그룹에 넣어라. " +
				"서비스로 돌린다면 LocalSystem 이어야 한다"
		}
	}
	// 코드를 못 알아보면 가장 흔한 원인을 안내한다.
	return "관리자 권한으로 실행해야 한다"
}
