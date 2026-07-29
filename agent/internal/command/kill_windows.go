//go:build windows

package command

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
// Windows 는 경로 대소문자를 구분하지 않으므로 매칭도 그렇게 한다.
func (ProcessKiller) Kill(target string) (string, string) {
	procs, err := listProcesses()
	if err != nil {
		return statusFailed, fmt.Sprintf("프로세스 목록을 읽지 못했다: %v", err)
	}
	return killMatching(target, procs, true, terminate)
}

var (
	kernel32                       = syscall.NewLazyDLL("kernel32.dll")
	procQueryFullProcessImageNameW = kernel32.NewProc("QueryFullProcessImageNameW")
)

// listProcesses 는 현재 프로세스의 PID 와 실행 파일 경로를 모은다.
//
// Toolhelp32 스냅샷은 실행 파일 이름만 준다. 전체 경로는 프로세스를 열어
// QueryFullProcessImageNameW 로 따로 물어봐야 한다. 대상이 경로로 지정될 수 있으니 필요하다.
func listProcesses() ([]process, error) {
	snapshot, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("프로세스 스냅샷 실패: %w", err)
	}
	defer syscall.CloseHandle(snapshot)

	var entry syscall.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := syscall.Process32First(snapshot, &entry); err != nil {
		return nil, fmt.Errorf("프로세스 목록 시작 실패: %w", err)
	}

	var out []process
	for {
		pid := int(entry.ProcessID)
		if pid > 0 {
			out = append(out, process{pid: pid, path: imagePath(pid, syscall.UTF16ToString(entry.ExeFile[:]))})
		}
		if err := syscall.Process32Next(snapshot, &entry); err != nil {
			break // ERROR_NO_MORE_FILES. 목록 끝이다
		}
	}
	return out, nil
}

// imagePath 는 PID 의 전체 실행 경로를 구한다.
// 권한이 없어 못 열면 스냅샷이 준 파일명으로 물러난다. 이름만으로도 매칭은 된다.
func imagePath(pid int, fallback string) string {
	const queryLimitedInformation = 0x1000
	handle, err := syscall.OpenProcess(queryLimitedInformation, false, uint32(pid))
	if err != nil {
		return fallback
	}
	defer syscall.CloseHandle(handle)

	buf := make([]uint16, syscall.MAX_LONG_PATH)
	size := uint32(len(buf))
	ret, _, _ := procQueryFullProcessImageNameW.Call(
		uintptr(handle), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if ret == 0 || size == 0 {
		return fallback
	}
	return syscall.UTF16ToString(buf[:size])
}

// terminate 는 프로세스를 강제 종료한다. Windows 에는 시그널이 없어 sig 는 쓰지 않는다.
func terminate(pid int, _ syscall.Signal) error {
	handle, err := syscall.OpenProcess(syscall.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("프로세스를 열 수 없다: %w", err)
	}
	defer syscall.CloseHandle(handle)
	if err := syscall.TerminateProcess(handle, 1); err != nil {
		return fmt.Errorf("종료 실패: %w", err)
	}
	return nil
}

// selfPID 는 자기 자신을 죽이지 않기 위한 값이다.
func selfPID() int { return os.Getpid() }
