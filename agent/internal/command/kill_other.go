//go:build !darwin && !windows

package command

import (
	"os"
	"runtime"
)

// unsupportedKiller 는 지원하지 않는 플랫폼에서 조치 요청을 거절한다.
//
// 대상은 macOS 와 Windows 뿐이다. 그래도 다른 OS 에서 빌드가 깨지지 않게 자리를 만들어 둔다.
// 조용히 성공을 보고하면 서버가 알림을 확인 처리해 버리므로, 분명히 실패로 답한다.
type unsupportedKiller struct{}

// NewKiller 는 이 플랫폼의 종료기를 만든다.
func NewKiller() Killer { return unsupportedKiller{} }

func (unsupportedKiller) Kill(string) (string, string) {
	return statusFailed, runtime.GOOS + " 에서는 프로세스 종료를 지원하지 않는다"
}

// selfPID 는 자기 자신을 죽이지 않기 위한 값이다.
func selfPID() int { return os.Getpid() }
