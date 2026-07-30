package main

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestOpenLogWriterEmptyPathUsesStderr(t *testing.T) {
	w, closeFn, err := openLogWriter("")
	if err != nil {
		t.Fatalf("openLogWriter: %v", err)
	}
	defer func() { _ = closeFn() }()

	if w != io.Writer(os.Stderr) {
		t.Errorf("경로가 비면 stderr 로 써야 한다, got %T", w)
	}
}

func TestOpenLogWriterCreatesFileAndParent(t *testing.T) {
	// 서비스로 뜰 때 상위 폴더가 아직 없을 수 있다. 거기서 죽으면 왜 안 뜨는지 볼 방법이 없다.
	path := filepath.Join(t.TempDir(), "sub", "agent.log")

	w, closeFn, err := openLogWriter(path)
	if err != nil {
		t.Fatalf("openLogWriter: %v", err)
	}
	if _, err := io.WriteString(w, "첫 줄\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := closeFn(); err != nil {
		t.Fatalf("close: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "첫 줄\n" {
		t.Errorf("파일 내용 = %q", got)
	}
}

func TestOpenLogWriterAppends(t *testing.T) {
	// 서비스가 재시작할 때마다 지우면 직전 실행이 왜 죽었는지가 사라진다.
	path := filepath.Join(t.TempDir(), "agent.log")
	if err := os.WriteFile(path, []byte("이전 실행\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	w, closeFn, err := openLogWriter(path)
	if err != nil {
		t.Fatalf("openLogWriter: %v", err)
	}
	_, _ = io.WriteString(w, "이번 실행\n")
	_ = closeFn()

	got, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(got), "이전 실행\n") {
		t.Errorf("이전 내용이 지워졌다: %q", got)
	}
	if !strings.Contains(string(got), "이번 실행") {
		t.Errorf("이번 내용이 없다: %q", got)
	}
}

func TestOpenLogWriterFileIsNotWorldReadable(t *testing.T) {
	// 로그에는 어느 호스트가 어디에 붙었는지가 남는다. 일반 사용자가 읽을 이유가 없다.
	if runtime.GOOS == "windows" {
		t.Skip("Windows 는 ACL 로 막는다. 설치 스크립트가 건다")
	}
	path := filepath.Join(t.TempDir(), "agent.log")

	_, closeFn, err := openLogWriter(path)
	if err != nil {
		t.Fatalf("openLogWriter: %v", err)
	}
	defer func() { _ = closeFn() }()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("권한 = %o, 소유자만 읽을 수 있어야 한다", perm)
	}
}

func TestOpenLogWriterReportsBadPath(t *testing.T) {
	// 열지 못하면 조용히 stderr 로 되돌리지 않는다. 로그가 파일에 있다고 믿고 찾는 쪽이
	// 아무것도 못 찾는 것보다, 지금 실패를 보는 편이 낫다.
	dir := t.TempDir()
	if _, _, err := openLogWriter(dir); err == nil {
		t.Error("폴더를 로그 파일로 열었는데 err 가 nil 이다")
	}
}
