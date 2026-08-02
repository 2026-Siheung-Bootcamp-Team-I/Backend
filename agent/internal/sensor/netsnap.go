package sensor

import (
	"net/netip"
	"time"

	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/event"
)

// netsnap 은 macOS 의 네트워크 연결을 짧은 주기 스냅샷으로 근사한다.
// 여기는 플랫폼 무관한 차분 로직만 두고, 실제 조회(libproc, cgo)는 netsnap_darwin.go 에 있다.

// Conn 은 한 시점에 관측된 연결 하나다.
type Conn struct {
	PID        int
	Path       string // 프로세스 실행 파일 경로
	RemoteIP   string
	RemotePort int
}

// connKey 는 두 스냅샷에서 같은 연결인지 가르는 기준이다.
// path 를 빼면 재사용된 PID 의 다른 프로세스가 같은 연결로 묶인다.
type connKey struct {
	pid  int
	path string
	ip   string
	port int
}

func (c Conn) key() connKey {
	return connKey{pid: c.PID, path: c.Path, ip: c.RemoteIP, port: c.RemotePort}
}

// Differ 는 직전 스냅샷을 쥐고 새로 생긴 연결만 골라낸다.
type Differ struct {
	seen      map[connKey]struct{}
	baselined bool
}

// NewDiffer 는 빈 차분기를 만든다.
func NewDiffer() *Differ {
	return &Differ{seen: make(map[connKey]struct{})}
}

// New 는 직전 스냅샷에 없던 연결만 돌려준다.
// 첫 호출은 기준선으로만 삼는다. 안 그러면 에이전트가 뜰 때 이미 열려 있던 연결 수백 개가 쏟아진다.
func (d *Differ) New(current []Conn) []Conn {
	next := make(map[connKey]struct{}, len(current))
	var fresh []Conn

	for _, c := range current {
		k := c.key()
		if _, dup := next[k]; dup {
			continue // 한 프로세스가 같은 목적지로 소켓을 여러 개 열면 이벤트가 그 수만큼 늘어난다
		}
		next[k] = struct{}{}
		if _, held := d.seen[k]; !held {
			fresh = append(fresh, c)
		}
	}

	// 통째로 갈아 끼워 사라진 연결을 버린다. 누적하면 맵이 프로세스 수명과 무관하게 계속 커진다.
	d.seen = next
	if !d.baselined {
		d.baselined = true
		return nil
	}
	return fresh
}

// Len 은 현재 스냅샷이 쥐고 있는 연결 수다. 맵이 새는지 확인하는 용도다.
func (d *Differ) Len() int { return len(d.seen) }

// IsPublic 은 공인 IP 인지 본다.
// 안 거르면 판정에 걸리지도 않는 사설/루프백 연결이 이벤트를 채운다.
func IsPublic(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	// ::ffff:10.0.0.1 같은 IPv4 매핑 주소는 풀어야 사설 대역 판정이 걸린다.
	addr = addr.Unmap()

	switch {
	case !addr.IsValid(), addr.IsUnspecified(): // 0.0.0.0, ::
		return false
	case addr.IsLoopback(): // 127.0.0.0/8, ::1
		return false
	case addr.IsPrivate(): // 10/8, 172.16/12, 192.168/16, fc00::/7
		return false
	case addr.IsLinkLocalUnicast(): // 169.254/16, fe80::/10
		return false
	case addr.IsMulticast(), addr.IsLinkLocalMulticast(), addr.IsInterfaceLocalMulticast():
		return false
	}
	return true
}

// ToEvents 는 새 연결을 서버로 보낼 이벤트로 바꾼다. 공인 IP 인 것만 남긴다.
// 프로토콜은 tcp 로 고정한다. 스냅샷이 established TCP 소켓만 모으기 때문이다.
func ToEvents(f event.Factory, at time.Time, conns []Conn) []event.Event {
	var events []event.Event
	for _, c := range conns {
		if !IsPublic(c.RemoteIP) {
			continue
		}
		events = append(events, f.Network(at, event.NetworkInfo{
			ProcessPath: c.Path,
			PID:         c.PID,
			Protocol:    event.ProtocolTCP,
			DestIP:      c.RemoteIP,
			DestPort:    c.RemotePort,
		}))
	}
	return events
}
