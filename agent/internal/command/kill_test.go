package command

import (
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
)

// killMatching 은 조치의 안전장치가 모여 있는 곳이다.
// 여기서 잘못 판단하면 멀쩡한 프로세스가 죽거나 에이전트 자신이 죽는다.

func recorder() (func(int, syscall.Signal) error, *[]int) {
	var killed []int
	return func(pid int, _ syscall.Signal) error {
		killed = append(killed, pid)
		return nil
	}, &killed
}

func TestKillsEveryMatchingProcess(t *testing.T) {
	// 같은 이름으로 여러 개가 떠 있으면 전부 죽여야 한다. 하나만 죽이면 공격이 계속된다.
	procs := []process{
		{pid: 100, path: "/tmp/evil.sh"},
		{pid: 101, path: "/tmp/evil.sh"},
		{pid: 102, path: "/usr/bin/curl"},
	}
	kill, killed := recorder()

	status, message := killMatching("/tmp/evil.sh", procs, false, kill)

	if status != statusKilled {
		t.Fatalf("status = %q (%s), want %q", status, message, statusKilled)
	}
	if len(*killed) != 2 {
		t.Errorf("죽인 pid = %v, want 100 과 101", *killed)
	}
}

func TestNeverKillsSelf(t *testing.T) {
	// 자기 자신을 죽이면 수집이 멈추고 다시 살아날 방법이 없다.
	procs := []process{{pid: os.Getpid(), path: "/usr/bin/edrdog-agent"}}
	kill, killed := recorder()

	status, _ := killMatching("edrdog-agent", procs, false, kill)

	if len(*killed) != 0 {
		t.Errorf("자기 자신을 죽였다: %v", *killed)
	}
	if status != statusNoMatch {
		t.Errorf("status = %q, want %q", status, statusNoMatch)
	}
}

func TestNeverKillsInit(t *testing.T) {
	// PID 1 은 launchd/init 이다. 죽이면 기기가 망가진다.
	procs := []process{{pid: 1, path: "/sbin/launchd"}, {pid: 0, path: "/kernel"}}
	kill, killed := recorder()

	killMatching("launchd", procs, false, kill)
	killMatching("kernel", procs, false, kill)

	if len(*killed) != 0 {
		t.Errorf("보호 대상 프로세스를 죽였다: %v", *killed)
	}
}

func TestNoMatchWhenNothingRuns(t *testing.T) {
	procs := []process{{pid: 100, path: "/usr/bin/curl"}}
	kill, killed := recorder()

	status, message := killMatching("/tmp/ghost.sh", procs, false, kill)

	if status != statusNoMatch {
		t.Errorf("status = %q, want %q", status, statusNoMatch)
	}
	if len(*killed) != 0 {
		t.Errorf("매칭이 없는데 죽였다: %v", *killed)
	}
	if !strings.Contains(message, "ghost.sh") {
		t.Errorf("메시지에 대상이 없다: %q", message)
	}
}

func TestFailedWhenKillErrors(t *testing.T) {
	procs := []process{{pid: 100, path: "/tmp/evil.sh"}}
	kill := func(int, syscall.Signal) error { return errors.New("권한 없음") }

	status, message := killMatching("/tmp/evil.sh", procs, false, kill)

	if status != statusFailed {
		t.Errorf("status = %q, want %q", status, statusFailed)
	}
	if !strings.Contains(message, "권한 없음") {
		t.Errorf("메시지에 원인이 없다: %q", message)
	}
}

func TestPartialKillIsFailure(t *testing.T) {
	// 일부만 죽었는데 KILLED 를 보고하면 서버가 알림을 확인 처리한다.
	// 대상 프로세스는 아직 살아 있는데 사람은 끝났다고 믿게 된다.
	procs := []process{
		{pid: 100, path: "/tmp/evil.sh"},
		{pid: 101, path: "/tmp/evil.sh"},
	}
	kill := func(pid int, _ syscall.Signal) error {
		if pid == 101 {
			return errors.New("권한 없음")
		}
		return nil
	}

	status, message := killMatching("/tmp/evil.sh", procs, false, kill)

	if status != statusFailed {
		t.Errorf("status = %q, want %q (%s)", status, statusFailed, message)
	}
}

func TestCaseInsensitiveMatchingOnWindows(t *testing.T) {
	procs := []process{{pid: 100, path: `C:\Windows\System32\CURL.EXE`}}
	kill, killed := recorder()

	if status, _ := killMatching("curl.exe", procs, true, kill); status != statusKilled {
		t.Errorf("Windows 에서 대소문자 무시 매칭이 안 됐다: %s", status)
	}
	if len(*killed) != 1 {
		t.Errorf("죽인 pid = %v", *killed)
	}
}
