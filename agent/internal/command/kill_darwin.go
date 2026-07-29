//go:build darwin

package command

/*
#include <libproc.h>
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// ProcessKiller 는 실행 중인 프로세스에서 대상을 찾아 종료한다.
//
// 탐지 시점의 PID 를 재사용하지 않고 조치 시점에 다시 찾는 이유는, 그 사이 원래 프로세스가
// 죽고 같은 PID 로 다른 프로세스가 떴을 수 있기 때문이다.
type ProcessKiller struct{}

// NewKiller 는 이 플랫폼의 종료기를 만든다.
func NewKiller() Killer { return ProcessKiller{} }

// Kill 은 target 과 일치하는 프로세스를 모두 종료한다.
func (ProcessKiller) Kill(target string) (string, string) {
	procs, err := listProcesses()
	if err != nil {
		return statusFailed, fmt.Sprintf("프로세스 목록을 읽지 못했다: %v", err)
	}
	return killMatching(target, procs, false, syscall.Kill)
}

// listProcesses 는 현재 프로세스의 PID 와 실행 파일 경로를 모은다.
//
// ps 를 서브프로세스로 띄우지 않는 이유는 출력 형식이 버전마다 다르고 경로에 공백이 있으면
// 파싱이 어긋나기 때문이다. libproc 은 경로를 그대로 준다.
func listProcesses() ([]process, error) {
	// 먼저 필요한 크기를 물어본 뒤, 그 사이 프로세스가 늘어날 수 있으므로 여유를 둔다.
	needed := C.proc_listpids(C.PROC_ALL_PIDS, 0, nil, 0)
	if needed <= 0 {
		return nil, fmt.Errorf("proc_listpids 가 크기를 주지 않았다")
	}
	count := int(needed)/int(unsafe.Sizeof(C.int(0))) + 64
	pids := make([]C.int, count)

	size := C.proc_listpids(C.PROC_ALL_PIDS, 0, unsafe.Pointer(&pids[0]), C.int(len(pids))*C.int(unsafe.Sizeof(C.int(0))))
	if size <= 0 {
		return nil, fmt.Errorf("proc_listpids 실패")
	}
	got := int(size) / int(unsafe.Sizeof(C.int(0)))

	path := make([]byte, C.PROC_PIDPATHINFO_MAXSIZE)
	out := make([]process, 0, got)
	for _, pid := range pids[:got] {
		if pid <= 0 {
			continue
		}
		n := C.proc_pidpath(pid, unsafe.Pointer(&path[0]), C.uint32_t(len(path)))
		if n <= 0 {
			continue // 권한이 없거나 이미 죽은 프로세스. 하나 때문에 전체를 실패시키지 않는다
		}
		out = append(out, process{pid: int(pid), path: string(path[:n])})
	}
	return out, nil
}

// selfPID 는 자기 자신을 죽이지 않기 위한 값이다.
func selfPID() int { return os.Getpid() }
