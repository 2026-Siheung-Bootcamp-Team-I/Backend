package sensor

import (
	"net/netip"
	"time"

	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/event"
)

// netsnap 은 macOS 의 네트워크 연결을 짧은 주기 스냅샷으로 근사한다.
//
// macOS 의 EndpointSecurity API 에는 소켓 연결 이벤트가 없다. 프로세스와 파일 중심이고,
// 진짜 연결 이벤트를 구독하려면 NetworkExtension entitlement 가 필요한데 학생 프로젝트는 받기 어렵다.
// 그래서 프로세스별로 열린 소켓을 주기마다 훑고, 직전 스냅샷에 없던 것만 새 연결로 본다.
//
// 이건 이 에이전트에서 유일하게 폴링인 부분이고 알려진 한계다. 주기 사이에 열렸다 닫힌 연결은
// 통째로 놓친다. 그래도 Zeek 처럼 패킷만 보는 것과 달리 어느 프로세스가 연결했는지는 알 수 있다.
//
// 이 파일에는 빌드 태그가 없다. 차분 로직은 플랫폼과 무관한 순수 함수라 어디서든 테스트된다.
// 실제 조회(libproc, cgo)는 netsnap_darwin.go 에 있다.

// Conn 은 한 시점에 관측된 연결 하나다.
type Conn struct {
	PID        int
	Path       string // 프로세스 실행 파일 경로
	RemoteIP   string
	RemotePort int
}

// connKey 는 두 스냅샷에서 같은 연결인지 가르는 기준이다.
//
// Path 가 들어 있는 이유는 PID 가 재사용되기 때문이다. 프로세스가 죽고 같은 PID 로 다른 프로세스가
// 뜨면 우연히 같은 목적지에 붙어도 다른 연결이다. 로컬 포트는 넣지 않는다. 판정에 쓰지 않는 값이라
// 넣어 봐야 같은 목적지로의 재접속을 새 이벤트로 늘릴 뿐이다.
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
//
// 첫 호출은 기준선으로만 삼고 아무것도 내지 않는다. 에이전트가 막 떴을 때 이미 열려 있던 연결
// 수백 개를 전부 이벤트로 쏟으면 그건 관측이 아니라 노이즈다. 에이전트 시작 전부터 있던 연결은
// 애초에 우리가 본 것이 아니다.
//
// 사라진 연결은 스냅샷에서 지운다. 안 그러면 맵이 프로세스 수명과 무관하게 계속 커진다.
// 지우기 때문에 끊겼다 다시 붙은 연결은 새 연결로 잡힌다. 그게 맞는 판단이다.
func (d *Differ) New(current []Conn) []Conn {
	next := make(map[connKey]struct{}, len(current))
	var fresh []Conn

	for _, c := range current {
		k := c.key()
		if _, dup := next[k]; dup {
			continue // 한 프로세스가 같은 목적지로 소켓을 여러 개 연 경우
		}
		next[k] = struct{}{}
		if _, held := d.seen[k]; !held {
			fresh = append(fresh, c)
		}
	}

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
//
// detector 의 위협 지도는 공인 IP 만 쓴다. 사설 대역이나 루프백 연결은 판정에 걸리지 않으면서
// 이벤트 수만 늘리는 노이즈다. 예전 osquery 쿼리도 127.0.0.1, ::1, 0.0.0.0 을 걸러 냈다.
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
func ToEvents(f event.Factory, at time.Time, conns []Conn) []event.Event {
	var events []event.Event
	for _, c := range conns {
		if !IsPublic(c.RemoteIP) {
			continue
		}
		events = append(events, f.Network(at, c.Path, c.RemoteIP, c.RemotePort))
	}
	return events
}
