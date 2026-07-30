//go:build darwin

package sensor

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/event"
)

// 진짜 eslogger 는 root 와 전체 디스크 접근 권한을 요구해서 테스트에서 띄울 수 없다.
// 대신 같은 자리에 가짜 실행 파일을 두고 프로세스 기동, 줄 읽기, 재기동, 실패 보고를 본다.
func eslFakeLogger(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fake-eslogger")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func eslQuietSensor(path string, watch []string) *ESLoggerSensor {
	return &ESLoggerSensor{
		Factory:      event.Factory{Host: "lab-mac"},
		WatchPaths:   watch,
		ESLoggerPath: path,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func TestESLoggerSensorName(t *testing.T) {
	s := &ESLoggerSensor{}
	if s.Name() != "eslogger" {
		t.Errorf("Name = %q, want eslogger", s.Name())
	}
}

func TestESLoggerSensorEmitsEventsAndStopsOnCancel(t *testing.T) {
	line := eslExecLine("/bin/zsh", "/tmp/evil.sh", `["evil.sh","--password","hunter2"]`)
	bin := eslFakeLogger(t, "echo '"+line+"'\necho '깨진 줄이라 그냥 지나가야 한다'\necho '"+line+"'\nsleep 30")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := make(chan event.Event, 16)
	done := make(chan error, 1)
	go func() { done <- eslQuietSensor(bin, nil).Run(ctx, out) }()

	for i := 0; i < 2; i++ {
		select {
		case e := <-out:
			if e.Type != event.TypeProcess {
				t.Errorf("Type = %q, want %q", e.Type, event.TypeProcess)
			}
			if e.Cmdline != "/tmp/evil.sh --password <redacted>" {
				t.Errorf("Cmdline = %q", e.Cmdline)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("이벤트가 오지 않았다")
		}
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ctx 를 끊었는데 멈추지 않았다")
	}
}

// 기본 64KB 버퍼로는 인자가 많은 프로세스의 줄이 잘려 통째로 버려진다.
func TestESLoggerSensorReadsVeryLongLine(t *testing.T) {
	longArg := strings.Repeat("a", 200*1024)
	line := eslExecLine("/bin/zsh", "/usr/bin/curl", `["curl","`+longArg+`"]`)

	payload := filepath.Join(t.TempDir(), "line.json")
	if err := os.WriteFile(payload, []byte(line+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := eslFakeLogger(t, "cat "+payload+"\nsleep 30")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := make(chan event.Event, 4)
	go func() { _ = eslQuietSensor(bin, nil).Run(ctx, out) }()

	select {
	case e := <-out:
		if len(e.Cmdline) < 200*1024 {
			t.Errorf("Cmdline 길이 = %d, 잘렸다", len(e.Cmdline))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("긴 줄에서 이벤트가 오지 않았다")
	}
}

// 조용히 0건이 되면 원인을 찾을 수 없다. 기동 실패는 반드시 오류로 올라와야 한다.
func TestESLoggerSensorReportsMissingBinary(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-eslogger")

	err := eslQuietSensor(missing, nil).Run(context.Background(), make(chan event.Event, 1))
	if err == nil {
		t.Fatal("없는 바이너리인데 오류가 없다")
	}
	if !strings.Contains(err.Error(), missing) {
		t.Errorf("오류에 경로가 없다: %v", err)
	}
}

func TestESLoggerSensorReportsPrivilegeFailureFromStderr(t *testing.T) {
	const msg = "Failed to create ES client: Not privileged to create an ES client, need to be superuser"
	bin := eslFakeLogger(t, "echo '"+msg+"' >&2\nexit 1")

	start := time.Now()
	err := eslQuietSensor(bin, nil).Run(context.Background(), make(chan event.Event, 1))
	if err == nil {
		t.Fatal("권한 실패인데 오류가 없다")
	}
	if !strings.Contains(err.Error(), "superuser") {
		t.Errorf("오류에 stderr 내용이 없다: %v", err)
	}
	// 한 줄도 못 읽었으면 재시도하지 않고 바로 올려야 한다.
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("재시도하느라 %v 걸렸다", elapsed)
	}
}

// 한 번이라도 정상 동작했으면 죽어도 다시 띄운다.
func TestESLoggerSensorRestartsAfterHealthyRun(t *testing.T) {
	dir := t.TempDir()
	counter := filepath.Join(dir, "runs")
	line := eslExecLine("/bin/zsh", "/usr/bin/whoami", `["whoami"]`)

	bin := eslFakeLogger(t,
		"n=$(cat "+counter+" 2>/dev/null || echo 0)\n"+
			"n=$((n+1))\n"+
			"echo $n > "+counter+"\n"+
			"echo '"+line+"'\n"+
			"if [ \"$n\" -ge 2 ]; then sleep 30; fi")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := make(chan event.Event, 16)
	done := make(chan error, 1)
	go func() { done <- eslQuietSensor(bin, nil).Run(ctx, out) }()

	for i := 0; i < 2; i++ {
		select {
		case <-out:
		case <-time.After(10 * time.Second):
			t.Fatalf("%d 번째 기동에서 이벤트가 오지 않았다", i+1)
		}
	}

	raw, err := os.ReadFile(counter)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(raw)); got != "2" {
		t.Errorf("기동 횟수 = %s, want 2", got)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ctx 를 끊었는데 멈추지 않았다")
	}
}

func TestESLoggerSensorFiltersFileEventsByWatchPaths(t *testing.T) {
	inside := eslCreateLine("/Library/LaunchAgents", "com.evil.plist")
	outside := eslCreateLine("/Users/lab/Downloads", "note.txt")
	bin := eslFakeLogger(t, "echo '"+outside+"'\necho '"+inside+"'\nsleep 30")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := make(chan event.Event, 8)
	go func() { _ = eslQuietSensor(bin, []string{"/Library/LaunchAgents"}).Run(ctx, out) }()

	select {
	case e := <-out:
		if e.Cmdline != "/Library/LaunchAgents/com.evil.plist" {
			t.Errorf("감시 대상 밖 이벤트가 섞였다: %q", e.Cmdline)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("이벤트가 오지 않았다")
	}
}
