package sensor

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

const (
	flowProc  = `C:\Program Files\Mozilla Firefox\firefox.exe`
	flowProc2 = `C:\Windows\System32\curl.exe`
)

// newTestFlowOwners 는 시계를 손으로 돌릴 수 있는 조회기를 만든다.
func newTestFlowOwners(clock *time.Time) *FlowOwners {
	f := NewFlowOwners()
	f.now = func() time.Time { return *clock }
	return f
}

func TestFlowOwnersJoinsConnectEventToSNI(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	f := newTestFlowOwners(&now)

	f.Remember(51000, testDstIP, portHTTPS, flowProc, now)

	// 연결 이벤트와 ClientHello 사이에는 최소 1 RTT 가 있다.
	now = now.Add(30 * time.Millisecond)
	if got := f.Lookup(51000, testDstIP, portHTTPS); got != flowProc {
		t.Errorf("조회 결과 = %q, 원하는 값 %q", got, flowProc)
	}
	if hits, misses := f.Stats(); hits != 1 || misses != 0 {
		t.Errorf("통계 = hits %d misses %d", hits, misses)
	}
}

func TestFlowOwnersDistinguishesFlows(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	f := newTestFlowOwners(&now)

	f.Remember(51000, testDstIP, portHTTPS, flowProc, now)
	f.Remember(51001, testDstIP, portHTTPS, flowProc2, now)

	if got := f.Lookup(51001, testDstIP, portHTTPS); got != flowProc2 {
		t.Errorf("51001 조회 = %q", got)
	}
	// 3-튜플 중 하나만 달라도 다른 흐름이다.
	for _, tc := range []struct {
		name                  string
		localPort, remotePort int
		remoteIP              string
	}{
		{"다른 로컬 포트", 51002, portHTTPS, testDstIP},
		{"다른 상대 IP", 51000, portHTTPS, "203.0.113.9"},
		{"다른 상대 포트", 51000, 8443, testDstIP},
	} {
		if got := f.Lookup(tc.localPort, tc.remoteIP, tc.remotePort); got != "" {
			t.Errorf("%s: 조회 = %q, 비어야 한다", tc.name, got)
		}
	}
}

func TestFlowOwnersDoesNotFallBackToLocalPort(t *testing.T) {
	// 로컬 포트만 맞으면 답해 주는 물러남을 두면, 이미 닫힌 연결의 프로세스를 같은 번호로
	// 새로 열린 연결에 붙이게 된다. 틀린 프로세스는 빈 값보다 나쁘다.
	now := time.Unix(1_700_000_000, 0)
	f := newTestFlowOwners(&now)

	f.Remember(51000, testDstIP, portHTTPS, flowProc, now)
	if got := f.Lookup(51000, "198.51.100.7", portHTTPS); got != "" {
		t.Errorf("상대가 다른데 %q 를 돌려줬다", got)
	}
}

func TestFlowOwnersExpires(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	f := newTestFlowOwners(&now)

	f.Remember(51000, testDstIP, portHTTPS, flowProc, now)

	// TTL 안이면 살아 있다.
	now = now.Add(flowOwnerTTL - time.Second)
	if got := f.Lookup(51000, testDstIP, portHTTPS); got != flowProc {
		t.Errorf("TTL 안인데 조회 = %q", got)
	}

	// TTL 을 넘기면 없는 것으로 본다.
	now = now.Add(2 * time.Second)
	if got := f.Lookup(51000, testDstIP, portHTTPS); got != "" {
		t.Errorf("TTL 을 넘겼는데 조회 = %q", got)
	}
	// 만료된 항목은 지워야 상한에 걸릴 때까지 자리를 차지하지 않는다.
	if n := f.Size(); n != 0 {
		t.Errorf("만료된 항목이 %d 개 남아 있다", n)
	}
}

func TestFlowOwnersNormalizesIPNotation(t *testing.T) {
	// 넣는 쪽은 ETW 가 렌더링한 문자열이고 찾는 쪽은 net.IP.String() 이 만든 문자열이다.
	// 표기만 다르고 같은 주소인 경우를 여기서 잡지 못하면 조인이 조용히 전부 빗나간다.
	cases := []struct {
		name       string
		remembered string
		looked     string
	}{
		{"IPv4 매핑 IPv6", "::ffff:93.184.216.34", "93.184.216.34"},
		{"IPv6 대문자", "2001:DB8::1", "2001:db8::1"},
		{"IPv6 축약 안 한 표기", "2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"},
		{"대괄호", "[2001:db8::1]", "2001:db8::1"},
		{"앞뒤 공백", " 93.184.216.34 ", "93.184.216.34"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Unix(1_700_000_000, 0)
			f := newTestFlowOwners(&now)

			f.Remember(51000, tc.remembered, portHTTPS, flowProc, now)
			if got := f.Lookup(51000, tc.looked, portHTTPS); got != flowProc {
				t.Errorf("%q 로 기억하고 %q 로 찾았더니 %q 가 나왔다", tc.remembered, tc.looked, got)
			}
		})
	}
}

func TestFlowOwnersIgnoresUnusableInput(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	f := newTestFlowOwners(&now)

	// 경로를 모르는 연결은 기억해 봐야 조회에 답하지 못한다.
	f.Remember(51000, testDstIP, portHTTPS, "", now)
	// IP 로 파싱되지 않는 값은 조인에 쓸 수 없다.
	f.Remember(51001, "not-an-ip", portHTTPS, flowProc, now)
	// 포트가 범위를 벗어나면 ETW 속성을 잘못 읽은 것이다.
	f.Remember(0, testDstIP, portHTTPS, flowProc, now)
	f.Remember(51002, testDstIP, 70000, flowProc, now)

	if n := f.Size(); n != 0 {
		t.Errorf("쓸 수 없는 입력이 %d 개 들어갔다", n)
	}
	if got := f.Lookup(51001, "not-an-ip", portHTTPS); got != "" {
		t.Errorf("조회 = %q", got)
	}
}

func TestFlowOwnersHonorsSizeLimit(t *testing.T) {
	// 신뢰할 수 없는 입력으로 커지는 맵이다. 상한이 없으면 연결을 마구 여는 프로그램 하나에
	// 에이전트가 메모리를 다 쓴다.
	now := time.Unix(1_700_000_000, 0)
	f := newTestFlowOwners(&now)

	for i := range flowOwnerMax * 2 {
		f.Remember(1024+i%60000, fmt.Sprintf("203.0.113.%d", i%256), portHTTPS, flowProc, now)
	}
	if n := f.Size(); n > flowOwnerMax {
		t.Errorf("항목이 %d 개다. 상한 %d 를 넘었다", n, flowOwnerMax)
	}

	// 상한에 닿아도 그 뒤에 들어온 연결은 정상적으로 찾혀야 한다.
	f.Remember(52000, "198.51.100.1", portHTTPS, flowProc2, now)
	if got := f.Lookup(52000, "198.51.100.1", portHTTPS); got != flowProc2 {
		t.Errorf("상한에 닿은 뒤 넣은 항목 조회 = %q", got)
	}
}

func TestFlowOwnersEvictsExpiredBeforeWiping(t *testing.T) {
	// 자리를 만들 때 만료된 것부터 지운다. 그래야 아직 쓸모 있는 최근 연결이 살아남는다.
	now := time.Unix(1_700_000_000, 0)
	f := newTestFlowOwners(&now)

	for i := range flowOwnerMax {
		f.Remember(1024+i, "203.0.113.1", portHTTPS, flowProc, now)
	}

	// 전부 만료시킨 뒤 최근 항목 하나를 넣는다.
	now = now.Add(flowOwnerTTL + time.Second)
	f.Remember(60000, "198.51.100.2", portHTTPS, flowProc2, now)

	if n := f.Size(); n != 1 {
		t.Errorf("항목이 %d 개다. 만료된 것을 지우고 새것 하나만 남아야 한다", n)
	}
	if got := f.Lookup(60000, "198.51.100.2", portHTTPS); got != flowProc2 {
		t.Errorf("새로 넣은 항목 조회 = %q", got)
	}
}

func TestFlowOwnersCountsMisses(t *testing.T) {
	// 이 비율이 실기기에서 확인할 값이다. 낮으면 연결 이벤트가 안 오는 것인지 순서가
	// 뒤집힌 것인지 따로 봐야 한다.
	now := time.Unix(1_700_000_000, 0)
	f := newTestFlowOwners(&now)

	f.Remember(51000, testDstIP, portHTTPS, flowProc, now)
	f.Lookup(51000, testDstIP, portHTTPS)
	f.Lookup(51001, testDstIP, portHTTPS)
	f.Lookup(51002, "bad", portHTTPS)

	if hits, misses := f.Stats(); hits != 1 || misses != 2 {
		t.Errorf("통계 = hits %d misses %d, 원하는 값 1/2", hits, misses)
	}
}

func TestRememberNetworkFlowReadsManifestProperties(t *testing.T) {
	// 속성 이름을 하나만 잘못 짚어도 조인이 통째로 빗나가고, 그건 오류가 아니라
	// "프로세스가 안 붙는다" 로만 보인다. 이름을 여기서 못 박아 둔다.
	// 매니페스트의 TCP 연결시도(12/28) 속성은 PID, size, daddr, saddr, dport, sport 다.
	now := time.Unix(1_700_000_000, 0)
	f := newTestFlowOwners(&now)

	props := map[string]string{
		"PID":   "4321",
		"size":  "52",
		"saddr": testSrcIP,
		"daddr": testDstIP,
		"sport": "51000",
		"dport": "443",
	}
	RememberNetworkFlow(f, props, fakeNamer{4321: flowProc}, now)

	if got := f.Lookup(51000, testDstIP, portHTTPS); got != flowProc {
		t.Errorf("조회 = %q, 원하는 값 %q", got, flowProc)
	}
}

func TestRememberNetworkFlowSkipsUnusableEvents(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	namer := fakeNamer{4321: flowProc}

	cases := []struct {
		name  string
		props map[string]string
	}{
		{"sport 없음", map[string]string{"PID": "4321", "daddr": testDstIP, "dport": "443"}},
		{"dport 없음", map[string]string{"PID": "4321", "daddr": testDstIP, "sport": "51000"}},
		{"PID 없음", map[string]string{"daddr": testDstIP, "sport": "51000", "dport": "443"}},
		{"daddr 없음", map[string]string{"PID": "4321", "sport": "51000", "dport": "443"}},
		{"포트가 숫자가 아님", map[string]string{"PID": "4321", "daddr": testDstIP, "sport": "x", "dport": "443"}},
		{"프로세스를 못 품", map[string]string{"PID": "9999", "daddr": testDstIP, "sport": "51000", "dport": "443"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newTestFlowOwners(&now)
			RememberNetworkFlow(f, tc.props, namer, now)
			if n := f.Size(); n != 0 {
				t.Errorf("쓸 수 없는 이벤트가 %d 개 기억됐다", n)
			}
		})
	}

	// namer 가 없으면 붙일 프로세스도 없다. nil 로 죽지 않아야 한다.
	f := newTestFlowOwners(&now)
	RememberNetworkFlow(f, map[string]string{"PID": "4321", "daddr": testDstIP, "sport": "51000", "dport": "443"}, nil, now)
	RememberNetworkFlow(nil, nil, namer, now)
}

func TestFlowOwnersIsSafeForConcurrentUse(t *testing.T) {
	// ETW 콜백과 L7 센서가 다른 고루틴이다. -race 로 돌려야 의미가 있다.
	f := NewFlowOwners()

	var wg sync.WaitGroup
	const workers = 8
	const rounds = 500

	for w := range workers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := range rounds {
				port := 10000 + w*rounds + i
				f.Remember(port, testDstIP, portHTTPS, flowProc, time.Now())
			}
		}(w)

		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := range rounds {
				f.Lookup(10000+w*rounds+i, testDstIP, portHTTPS)
				f.Size()
				f.Stats()
			}
		}(w)
	}
	wg.Wait()
}

// FlowOwners 가 SocketOwner 를 만족하는지는 컴파일 시점에 못 박는다.
// L7Sensor 에 넘기는 순간 깨지는 것보다 여기서 깨지는 편이 낫다.
var _ SocketOwner = (*FlowOwners)(nil)
