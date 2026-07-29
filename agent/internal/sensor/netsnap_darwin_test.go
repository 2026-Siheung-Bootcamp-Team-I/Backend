//go:build darwin

package sensor

import (
	"context"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/event"
	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/runtime"
)

// 런타임에 그대로 꽂을 수 있어야 한다.
var _ runtime.Sensor = (*NetSnapSensor)(nil)

func TestNetSnapSensorStopsOnContextCancel(t *testing.T) {
	// 주기를 길게 잡으면 첫 스냅샷(기준선)만 뜨고 바로 대기에 들어간다.
	s := &NetSnapSensor{Factory: event.Factory{Host: "lab"}, Interval: time.Hour}
	out := make(chan event.Event, 16)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, out) }()
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Error("취소로 끝났는데 err 가 nil 이다")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("취소 후에도 안 멈췄다")
	}

	if n := len(out); n != 0 {
		t.Errorf("기준선 주기에서 이벤트 %d 건이 나왔다", n)
	}
}

// TestSnapshotSeesOwnConnection 은 libproc 배선이 실제로 도는지 본다.
//
// 루프백으로 연결을 하나 열어 두고 스냅샷에 그 연결이 잡히는지만 확인한다. 바깥 네트워크를
// 쓰지 않으므로 CI 에서도 돌고, sudo 없이도 자기 프로세스의 소켓은 보인다.
// 루프백이라 ToEvents 는 이 연결을 걸러 내지만, 여기서 확인하려는 것은 조회 경로다.
func TestSnapshotSeesOwnConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("리스너를 못 열었다: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("연결을 못 걸었다: %v", err)
	}
	defer client.Close()

	server := <-accepted
	if server == nil {
		t.Fatal("서버 쪽 연결을 못 받았다")
	}
	defer server.Close()

	conns, err := snapshot()
	if err != nil {
		t.Fatalf("snapshot 이 실패했다: %v", err)
	}
	if len(conns) == 0 {
		t.Fatal("연결을 한 건도 못 봤다")
	}

	me := os.Getpid()
	_, wantPort, _ := net.SplitHostPort(ln.Addr().String())

	found := false
	for _, c := range conns {
		if c.PID != me {
			continue
		}
		if c.Path == "" {
			t.Errorf("PID %d 의 실행 파일 경로가 비었다", c.PID)
		}
		if c.RemoteIP == "127.0.0.1" && strconv.Itoa(c.RemotePort) == wantPort {
			found = true
		}
	}
	if !found {
		t.Errorf("방금 연 127.0.0.1:%s 연결이 스냅샷에 없다 (내 PID %d, 전체 %d 건)", wantPort, me, len(conns))
	}
}
