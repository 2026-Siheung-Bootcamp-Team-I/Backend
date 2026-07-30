package sensor

import (
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// 이 파일에는 빌드 태그가 없다. 채워 넣는 쪽만 Windows 전용이고 판정은 아니다.
//
// Windows 에서 TLS SNI 에 프로세스를 붙이는 방법은 macOS 와 다르다. macOS 는 ClientHello 를
// 본 그 순간 열려 있는 소켓을 전부 훑어 주인을 찾지만(pcap_darwin.go 의 ProcOwner),
// Windows 는 그럴 필요가 없다. Microsoft-Windows-Kernel-Network 의 연결 이벤트가 이미
// PID 를 실어 주기 때문이다. 그 값을 잠깐 들고 있다가 SNI 가 올 때 이어 붙이면 된다.

const (
	// flowOwnerTTL 은 기억한 연결을 얼마나 믿을지다.
	//
	// 짧게 잡으면 안 되는 이유는 도착 순서가 뒤집힐 수 있어서다. 프로토콜상으로는 연결
	// 이벤트가 ClientHello 보다 반드시 먼저 생긴다. ClientHello 는 3-way handshake 가 끝난
	// 뒤에 나가고 연결 이벤트는 커널이 SYN 을 낼 때 나므로 최소 1 RTT 차이가 난다.
	// 그런데 ETW 실시간 세션은 프로세서마다 버퍼를 따로 두고 기본 1초 주기로 비우기 때문에
	// 만들어진 순서와 배달되는 순서가 다를 수 있다(MS 문서도 ProcessTrace 가 순서를
	// 보장하지 않는다고 적어 두었다). 먼저 만들어진 것을 나중에 받는 쪽은 이 캐시로 못 막고,
	// 먼저 받아 둔 것을 나중에 쓰는 쪽만 이 캐시가 막아 준다. 그래서 넉넉히 잡는다.
	//
	// 길게 잡아도 되는 이유는 포트 재사용이다. Windows 의 기본 동적 포트 범위는 16384개인데
	// 60초 안에 그걸 한 바퀴 돌리려면 초당 273개 연결을 그 시간 내내 유지해야 한다.
	// 사람이 쓰는 단말에서 나올 수치가 아니다.
	flowOwnerTTL = 60 * time.Second

	// flowOwnerMax 는 기억할 연결 수 상한이다.
	//
	// 상한이 반드시 필요한 이유는 이 맵이 바깥에서 오는 입력으로 커지기 때문이다. 연결을
	// 마구 여는 프로그램(또는 그렇게 하는 악성코드)이 있으면 상한이 없는 맵은 그대로 메모리를
	// 먹는다. 관측하려고 켜 둔 에이전트가 관측 대상 때문에 죽으면 안 된다.
	flowOwnerMax = 8192
)

// flowOwnerKey 는 흐름 하나를 가리킨다.
//
// 출발지 IP 는 넣지 않는다. 연결 이벤트의 saddr 과 캡처한 프레임의 출발지 IP 는 같은 값이어야
// 맞지만, 그 사이에 NAT 나 가상 스위치가 끼면 달라질 수 있다. 로컬 포트와 상대 주소 셋이면
// 한 기기 안에서 흐름을 가리기에 이미 충분하다.
type flowOwnerKey struct {
	localPort  int
	remoteIP   string
	remotePort int
}

type flowOwnerEntry struct {
	path string
	at   time.Time
}

// FlowOwners 는 연결 이벤트가 알려 준 (흐름 → 프로세스) 를 잠시 들고 있는다.
//
// ETW 콜백과 L7 센서가 서로 다른 고루틴이라 뮤텍스로 감싼다.
type FlowOwners struct {
	mu      sync.Mutex
	entries map[flowOwnerKey]flowOwnerEntry

	// now 가 비면 time.Now 를 쓴다. 만료를 테스트에서 흔들어 보려고 둔다.
	now func() time.Time

	hits   atomic.Uint64
	misses atomic.Uint64
}

// NewFlowOwners 는 조회기를 만든다.
func NewFlowOwners() *FlowOwners {
	return &FlowOwners{entries: make(map[flowOwnerKey]flowOwnerEntry)}
}

// Remember 는 연결 이벤트를 기록한다. ETW 쪽이 부른다.
//
// 경로를 모르는 연결은 기록하지 않는다. 프로세스가 이미 죽어 조회에 실패한 경우인데,
// 그걸 넣어 두면 자리만 차지하고 조회에 답해 주지도 못한다.
func (f *FlowOwners) Remember(localPort int, remoteIP string, remotePort int, path string, now time.Time) {
	if path == "" {
		return
	}
	key, ok := newFlowOwnerKey(localPort, remoteIP, remotePort)
	if !ok {
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if f.entries == nil {
		f.entries = make(map[flowOwnerKey]flowOwnerEntry)
	}
	if len(f.entries) >= flowOwnerMax {
		f.evict(now)
	}
	f.entries[key] = flowOwnerEntry{path: path, at: now}
}

// Lookup 은 흐름의 주인 프로세스 경로를 찾는다. 못 찾으면 빈 문자열이다. SocketOwner 를 만족한다.
//
// **로컬 포트만으로 다시 찾아보는 물러남을 두지 않는다.** macOS 의 ProcOwner 에는 그런 물러남이
// 있는데 거기는 지금 열려 있는 소켓만 훑은 결과라 안전하다. 여기 들어 있는 것은 최대 60초 전의
// 기억이라, 포트만 맞춰 답하면 이미 닫힌 연결의 프로세스를 새 연결에 붙일 수 있다.
// 틀린 프로세스는 빈 값보다 나쁘다. 조사하는 사람이 그 값을 믿고 엉뚱한 곳을 파기 때문이다.
func (f *FlowOwners) Lookup(localPort int, remoteIP string, remotePort int) string {
	key, ok := newFlowOwnerKey(localPort, remoteIP, remotePort)
	if !ok {
		f.misses.Add(1)
		return ""
	}

	now := f.clock()

	f.mu.Lock()
	defer f.mu.Unlock()

	entry, found := f.entries[key]
	if !found {
		f.misses.Add(1)
		return ""
	}
	if now.Sub(entry.at) > flowOwnerTTL {
		// 만료된 기억은 지운다. 안 지우면 상한에 걸릴 때까지 자리를 차지한다.
		delete(f.entries, key)
		f.misses.Add(1)
		return ""
	}

	f.hits.Add(1)
	return entry.path
}

// Stats 는 지금까지의 조회 성공/실패 수다.
//
// 이 값을 밖으로 내는 이유는 실기기에서 확인할 것이 "SNI 에 프로세스가 붙는 비율" 이기
// 때문이다. 붙지 않는 이벤트가 많을 때 그게 연결 이벤트를 못 받아서인지, 받았는데 순서가
// 뒤집혀서인지 가리려면 먼저 비율부터 알아야 한다.
func (f *FlowOwners) Stats() (hits, misses uint64) {
	return f.hits.Load(), f.misses.Load()
}

// Size 는 지금 들고 있는 항목 수다. 상한이 실제로 먹는지 보려고 둔다.
func (f *FlowOwners) Size() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.entries)
}

// evict 는 자리를 만든다. 호출자가 락을 쥐고 있어야 한다.
//
// 먼저 만료된 것만 지운다. 그러고도 자리가 안 나면 맵을 통째로 버린다. 통째로 버리는 것이
// 거칠어 보이지만, 상한에 닿았다는 것은 연결이 비정상적으로 쏟아지고 있다는 뜻이라 그 상황에서
// 정교한 축출을 하느라 락을 오래 쥐고 있는 편이 더 나쁘다. 잃는 것은 잠깐의 프로세스 귀속이고,
// SNI 이벤트 자체는 프로세스 없이도 그대로 나간다.
func (f *FlowOwners) evict(now time.Time) {
	for k, e := range f.entries {
		if now.Sub(e.at) > flowOwnerTTL {
			delete(f.entries, k)
		}
	}
	if len(f.entries) >= flowOwnerMax {
		f.entries = make(map[flowOwnerKey]flowOwnerEntry, flowOwnerMax)
	}
}

func (f *FlowOwners) clock() time.Time {
	if f.now != nil {
		return f.now()
	}
	return time.Now()
}

// RememberNetworkFlow 는 Kernel-Network 연결 이벤트 속성에서 흐름과 프로세스를 뽑아 기억한다.
//
// 배선이 아니라 여기에 두는 이유는 검증 때문이다. 속성 이름을 하나만 잘못 짚어도 조인이
// 통째로 빗나가는데 그건 오류가 아니라 "프로세스가 안 붙는다" 로만 보인다. 속성 맵을 받는
// 순수 함수로 만들어 두면 개발 기기에서 그 이름들을 못 박아 둘 수 있다.
//
// 매니페스트의 속성 이름은 12(IPv4)와 28(IPv6)이 같다: PID, size, daddr, saddr, dport, sport.
//
// saddr 은 쓰지 않는다. 키에 넣지 않기로 한 이유는 flowOwnerKey 주석에 적었다.
// 포트에 ntohs 를 걸지 않는 이유는 MapNetwork 주석과 같다. TDH 가 렌더링해 준 값이라
// 이미 호스트 바이트 오더의 십진수다.
func RememberNetworkFlow(f *FlowOwners, props map[string]string, namer ProcessNamer, now time.Time) {
	if f == nil || namer == nil {
		return
	}
	localPort, ok := parsePort(prop(props, propSrcPort))
	if !ok {
		return
	}
	remotePort, ok := parsePort(prop(props, propDestPort))
	if !ok {
		return
	}
	pid, ok := parsePID(prop(props, propPID))
	if !ok {
		return
	}
	// 경로 해석은 캐시(pidCache)를 거친다. 곧이어 MapNetwork 도 같은 PID 를 풀기 때문에
	// 여기서 한 번 풀어 두면 그쪽은 캐시에 맞고, 실제 프로세스 조회 횟수는 늘지 않는다.
	f.Remember(localPort, prop(props, propDestAddr), remotePort, namer.Name(pid), now)
}

// parsePort 는 포트 속성을 읽는다. 범위를 벗어나면 두 번째 값이 false 다.
func parsePort(raw string) (int, bool) {
	port, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || port <= 0 || port > 65535 {
		return 0, false
	}
	return port, true
}

// newFlowOwnerKey 는 조회 키를 만든다. 쓸 수 없는 값이면 두 번째 값이 false 다.
func newFlowOwnerKey(localPort int, remoteIP string, remotePort int) (flowOwnerKey, bool) {
	if localPort <= 0 || localPort > 65535 || remotePort <= 0 || remotePort > 65535 {
		return flowOwnerKey{}, false
	}
	ip := normalizeFlowIP(remoteIP)
	if ip == "" {
		return flowOwnerKey{}, false
	}
	return flowOwnerKey{localPort: localPort, remoteIP: ip, remotePort: remotePort}, true
}

// normalizeFlowIP 는 양쪽에서 온 IP 표기를 같은 모양으로 맞춘다.
//
// 이게 없으면 조인이 조용히 빗나간다. 넣는 쪽은 ETW 가 렌더링한 문자열이고 찾는 쪽은
// net.IP.String() 이 만든 문자열이라 같은 주소를 다르게 적을 수 있다. IPv6 의 축약 위치나
// 대소문자가 그렇고, IPv4 매핑 주소가 "::ffff:1.2.3.4" 로 오는 경우도 그렇다.
// 문자열끼리 비교하지 말고 주소로 파싱한 뒤 한 가지 표기로 되돌린다.
func normalizeFlowIP(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	// ETW 속성이 "[2001:db8::1]" 처럼 대괄호를 달고 오는 경우가 있다.
	s = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")

	ip := net.ParseIP(s)
	if ip == nil {
		return ""
	}
	// IPv4 매핑 IPv6 는 IPv4 로 되돌린다. 같은 주소를 두 모양으로 기억하지 않기 위해서다.
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}
