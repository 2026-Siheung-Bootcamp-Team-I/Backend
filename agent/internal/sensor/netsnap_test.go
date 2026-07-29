package sensor

import (
	"testing"
	"time"

	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/event"
)

func conn(pid int, path, ip string, port int) Conn {
	return Conn{PID: pid, Path: path, RemoteIP: ip, RemotePort: port}
}

func TestDifferFirstSnapshotIsBaseline(t *testing.T) {
	d := NewDiffer()

	got := d.New([]Conn{
		conn(10, "/usr/bin/curl", "203.0.113.1", 443),
		conn(11, "/usr/bin/ssh", "198.51.100.7", 22),
	})

	if len(got) != 0 {
		t.Fatalf("첫 스냅샷에서 %d 건이 나왔다, 기준선이라 0 이어야 한다: %v", len(got), got)
	}
}

func TestDifferReportsOnlyNewConns(t *testing.T) {
	d := NewDiffer()
	old := conn(10, "/usr/bin/curl", "203.0.113.1", 443)
	d.New([]Conn{old})

	fresh := conn(11, "/usr/bin/ssh", "198.51.100.7", 22)
	got := d.New([]Conn{old, fresh})

	if len(got) != 1 || got[0] != fresh {
		t.Fatalf("New = %v, want [%v]", got, fresh)
	}
}

func TestDifferSuppressesHeldConn(t *testing.T) {
	d := NewDiffer()
	held := conn(10, "/usr/bin/ssh", "198.51.100.7", 22)
	d.New([]Conn{held})

	// 오래 유지되는 연결이 주기마다 새 이벤트로 나오면 안 된다.
	for i := 0; i < 3; i++ {
		if got := d.New([]Conn{held}); len(got) != 0 {
			t.Fatalf("%d 번째 재관측에서 %v 가 다시 나왔다", i+1, got)
		}
	}
}

func TestDifferForgetsGoneConn(t *testing.T) {
	d := NewDiffer()
	c := conn(10, "/usr/bin/curl", "203.0.113.1", 443)
	d.New([]Conn{c})

	if got := d.New(nil); len(got) != 0 {
		t.Fatalf("연결이 사라진 주기에 %v 가 나왔다", got)
	}
	// 끊겼다 다시 붙은 것은 새 연결이다.
	got := d.New([]Conn{c})
	if len(got) != 1 || got[0] != c {
		t.Fatalf("재접속을 못 잡았다: New = %v", got)
	}
}

func TestDifferDropsGoneConnFromSnapshot(t *testing.T) {
	d := NewDiffer()
	d.New([]Conn{
		conn(10, "/usr/bin/curl", "203.0.113.1", 443),
		conn(11, "/usr/bin/ssh", "198.51.100.7", 22),
	})
	kept := conn(11, "/usr/bin/ssh", "198.51.100.7", 22)
	d.New([]Conn{kept})

	if n := d.Len(); n != 1 {
		t.Fatalf("스냅샷에 %d 건이 남았다, 사라진 연결을 지웠다면 1 이어야 한다", n)
	}
}

func TestDifferTreatsReusedPIDAsNew(t *testing.T) {
	d := NewDiffer()
	d.New([]Conn{conn(10, "/usr/bin/curl", "203.0.113.1", 443)})

	// PID 는 재사용된다. 같은 PID 라도 실행 파일이 다르면 다른 프로세스의 다른 연결이다.
	reused := conn(10, "/tmp/evil", "203.0.113.1", 443)
	got := d.New([]Conn{reused})
	if len(got) != 1 || got[0] != reused {
		t.Fatalf("PID 재사용을 새 연결로 안 봤다: New = %v", got)
	}
}

func TestIsPublic(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", false},
		{"::1", false},
		{"0.0.0.0", false},
		{"::", false},
		{"10.0.0.5", false},
		{"192.168.1.10", false},
		{"172.16.0.1", false},
		{"172.31.255.254", false},
		{"169.254.10.1", false},
		{"fe80::1", false},
		{"fd00::1", false},
		{"224.0.0.1", false},
		{"ff02::1", false},
		{"", false},
		{"어쩌구", false},
		{"::ffff:127.0.0.1", false},
		{"::ffff:10.0.0.1", false},

		{"8.8.8.8", true},
		{"203.0.113.1", true},
		{"172.32.0.1", true},
		{"2001:4860:4860::8888", true},
		{"::ffff:8.8.8.8", true},
	}

	for _, tt := range tests {
		if got := IsPublic(tt.ip); got != tt.want {
			t.Errorf("IsPublic(%q) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestToEventsKeepsOnlyPublic(t *testing.T) {
	at := time.UnixMilli(1785341400000)
	f := event.Factory{Host: "lab-mac"}

	got := ToEvents(f, at, []Conn{
		conn(10, "/usr/bin/curl", "203.0.113.1", 443),
		conn(11, "/usr/sbin/mDNSResponder", "192.168.0.1", 53),
		conn(12, "/usr/bin/ssh", "127.0.0.1", 22),
	})

	if len(got) != 1 {
		t.Fatalf("이벤트 %d 건, 공인 IP 하나만 남아야 한다: %v", len(got), got)
	}
	want := event.Event{
		Host:     "lab-mac",
		Type:     event.TypeNetwork,
		TS:       1785341400000,
		Process:  "curl", // 전체 경로가 아니라 basename
		DestIP:   "203.0.113.1",
		DestPort: 443,
	}
	if got[0] != want {
		t.Errorf("ToEvents[0] = %+v, want %+v", got[0], want)
	}
}

func TestToEventsOnEmpty(t *testing.T) {
	if got := ToEvents(event.Factory{Host: "lab-mac"}, time.Now(), nil); len(got) != 0 {
		t.Errorf("빈 입력에 %v 가 나왔다", got)
	}
}
