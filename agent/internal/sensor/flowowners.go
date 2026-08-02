package sensor

import (
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Windows 의 Kernel-Network 연결 이벤트가 알려 준 PID 를 잠시 들고 있다가 SNI 에 이어 붙인다.

const (
	// flowOwnerTTL 은 기억한 연결을 얼마나 믿을지다.
	// 짧게 줄이면 ETW 배달 순서가 뒤집힐 때 SNI 에 프로세스가 안 붙는다.
	flowOwnerTTL = 60 * time.Second

	// flowOwnerMax 는 기억할 연결 수 상한이다.
	// 이 맵은 바깥 입력으로 커진다. 상한을 풀면 연결을 마구 여는 프로그램이 메모리를 먹는다.
	flowOwnerMax = 8192
)

// flowOwnerKey 는 흐름 하나를 가리킨다.
// 출발지 IP 를 넣으면 NAT 나 가상 스위치가 끼는 순간 조인이 조용히 빗나간다.
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
// 경로 없는 연결은 담지 않는다. 담아 봐야 조회에 답도 못 하면서 상한만 갉아먹는다.
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
// 로컬 포트만으로 다시 찾아보는 물러남은 두지 않는다. 틀린 프로세스는 빈 값보다 나쁘다.
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
func (f *FlowOwners) Stats() (hits, misses uint64) {
	return f.hits.Load(), f.misses.Load()
}

// Size 는 지금 들고 있는 항목 수다. 상한이 실제로 먹는지 보려고 둔다.
func (f *FlowOwners) Size() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.entries)
}

// evict 는 만료된 것을 지우고, 그래도 자리가 안 나면 맵을 통째로 버린다.
// 호출자가 락을 쥐고 있어야 한다.
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
// 속성 이름은 12(IPv4)와 28(IPv6)이 같다: PID, size, daddr, saddr, dport, sport.
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
	// 경로 해석은 캐시(pidCache)를 거친다. MapNetwork 가 같은 PID 를 풀 때 캐시에 맞는다.
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
// 표기가 어긋나면 조인이 조용히 빗나가므로 문자열 비교 대신 파싱해서 되돌린다.
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
