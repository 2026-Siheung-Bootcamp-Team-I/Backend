package sensor

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/event"
	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/packet"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	testHost   = "mac-01"
	testSrcIP  = "10.0.0.5"
	testResIP  = "1.1.1.1"
	testDstIP  = "93.184.216.34"
	testSrcPrt = 51000
)

// fakeSource 는 미리 정해 둔 프레임을 흘려보내는 가짜 캡처다.
type fakeSource struct {
	ch chan []byte

	mu     sync.Mutex
	closed bool
}

func newFakeSource() *fakeSource {
	return &fakeSource{ch: make(chan []byte, 64)}
}

func (f *fakeSource) Packets() <-chan []byte { return f.ch }

func (f *fakeSource) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeSource) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// fakeOwner 는 로컬 포트로 프로세스를 찾는 가짜 조회기다.
type fakeOwner struct {
	byPort map[int]string

	mu    sync.Mutex
	calls []int
}

func (o *fakeOwner) Lookup(localPort int, remoteIP string, remotePort int) string {
	o.mu.Lock()
	o.calls = append(o.calls, localPort)
	o.mu.Unlock()
	return o.byPort[localPort]
}

func (o *fakeOwner) callCount() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.calls)
}

// runSensor 는 센서를 띄워 프레임을 먹이고 나온 이벤트를 모은다.
//
// 더 이상 이벤트가 안 나오면 멈춘다. 프레임 한 장이 이벤트 0개나 1개를 내는 구조라
// "몇 개 나올 때까지" 로는 기다릴 수 없다. 안 나와야 정답인 경우가 절반이다.
func runSensor(t *testing.T, s *L7Sensor, src *fakeSource, frames ...[]byte) []event.Event {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := make(chan event.Event, 64)
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, out) }()

	for _, f := range frames {
		src.ch <- f
	}

	var got []event.Event
	idle := time.NewTimer(250 * time.Millisecond)
	defer idle.Stop()
	for {
		select {
		case e := <-out:
			got = append(got, e)
			if !idle.Stop() {
				<-idle.C
			}
			idle.Reset(250 * time.Millisecond)
		case <-idle.C:
			cancel()
			<-done
			return got
		}
	}
}

// newTestSensor 는 가짜 캡처와 가짜 소유자 조회기를 단 센서를 만든다.
func newTestSensor(owner SocketOwner) (*L7Sensor, *fakeSource) {
	src := newFakeSource()
	return &L7Sensor{
		Factory:  event.Factory{Host: testHost},
		Source:   src,
		Owner:    owner,
		LinkType: packet.LinkEthernet,
	}, src
}

func TestL7SensorEmitsDNSResponse(t *testing.T) {
	s, src := newTestSensor(nil)
	frame := ipv4Frame(testResIP, testSrcIP,
		udpSegment(53, testSrcPrt, dnsResponse(t, "example.com", dnsmessage.TypeA, "93.184.216.34", "93.184.216.35")))

	got := runSensor(t, s, src, frame)
	if len(got) != 1 {
		t.Fatalf("이벤트 %d 개, 원하는 값 1개: %+v", len(got), got)
	}

	e := got[0]
	if e.Type != event.TypeDNS {
		t.Errorf("타입 = %q", e.Type)
	}
	if e.Host != testHost {
		t.Errorf("호스트 = %q", e.Host)
	}
	if e.Domain != "example.com" {
		t.Errorf("도메인 = %q", e.Domain)
	}
	// macOS 의 DNS 는 전부 mDNSResponder 를 거치므로 소켓 주인이 실제 질의자가 아니다.
	// 그래서 프로세스를 일부러 비운다.
	if e.Process != "" {
		t.Errorf("프로세스 = %q, 비어 있어야 한다", e.Process)
	}

	detail := decodeDetail(t, e.Detail)
	if detail["queryType"] != "A" {
		t.Errorf("queryType = %v", detail["queryType"])
	}
	// 프로토콜은 지어낸 값이 아니라 패킷에서 본 것이다.
	if detail["protocol"] != "udp" {
		t.Errorf("protocol = %v, want udp", detail["protocol"])
	}
	answers, _ := detail["answers"].([]any)
	if len(answers) != 2 || answers[0] != "93.184.216.34" || answers[1] != "93.184.216.35" {
		t.Errorf("answers = %v", detail["answers"])
	}
}

func TestL7SensorIgnoresDNSQuery(t *testing.T) {
	// 질의와 응답을 둘 다 내면 같은 도메인이 두 번 올라간다. 응답 쪽만 낸다.
	s, src := newTestSensor(nil)
	frame := ipv4Frame(testSrcIP, testResIP,
		udpSegment(testSrcPrt, 53, dnsQuery(t, "example.com", dnsmessage.TypeA)))

	if got := runSensor(t, s, src, frame); len(got) != 0 {
		t.Fatalf("질의에서 이벤트가 %d 개 나왔다: %+v", len(got), got)
	}
}

func TestL7SensorKeepsNXDOMAINResponse(t *testing.T) {
	// 응답만 낸다는 규칙 때문에 없는 도메인 질의까지 잃으면 곤란하다. NXDOMAIN 도 응답이라 잡힌다.
	s, src := newTestSensor(nil)
	frame := ipv4Frame(testResIP, testSrcIP,
		udpSegment(53, testSrcPrt, dnsResponse(t, "nope.example.com", dnsmessage.TypeA)))

	got := runSensor(t, s, src, frame)
	if len(got) != 1 {
		t.Fatalf("이벤트 %d 개: %+v", len(got), got)
	}
	if got[0].Domain != "nope.example.com" {
		t.Errorf("도메인 = %q", got[0].Domain)
	}
	if detail := decodeDetail(t, got[0].Detail); detail["answers"] != nil {
		t.Errorf("응답 IP 가 없어야 하는데 %v 다", detail["answers"])
	}
}

func TestL7SensorEmitsSNIWithProcess(t *testing.T) {
	owner := &fakeOwner{byPort: map[int]string{testSrcPrt: "/Applications/Firefox.app/Contents/MacOS/firefox"}}
	s, src := newTestSensor(owner)
	frame := ipv4Frame(testSrcIP, testDstIP,
		tcpSegment(testSrcPrt, 443, clientHello(t, "example.com")))

	got := runSensor(t, s, src, frame)
	if len(got) != 1 {
		t.Fatalf("이벤트 %d 개: %+v", len(got), got)
	}

	e := got[0]
	if e.Type != event.TypeL7 {
		t.Errorf("타입 = %q", e.Type)
	}
	if e.Domain != "example.com" {
		t.Errorf("도메인 = %q", e.Domain)
	}
	if e.Process != "firefox" {
		t.Errorf("프로세스 = %q", e.Process)
	}
	if e.DestIP != testDstIP || e.DestPort != 443 {
		t.Errorf("목적지 = %s:%d", e.DestIP, e.DestPort)
	}
	detail := decodeDetail(t, e.Detail)
	if detail["protocol"] != "tcp" {
		t.Errorf("protocol = %v, want tcp", detail["protocol"])
	}
	if detail["tlsVersion"] != "TLS 1.3" {
		t.Errorf("tlsVersion = %v", detail["tlsVersion"])
	}
	alpn, _ := detail["alpn"].([]any)
	if len(alpn) != 2 || alpn[0] != "h2" || alpn[1] != "http/1.1" {
		t.Errorf("alpn = %v", detail["alpn"])
	}
	if owner.callCount() != 1 {
		t.Errorf("소유자 조회 %d 회, ClientHello 를 본 그 순간 한 번이어야 한다", owner.callCount())
	}
}

func TestL7SensorEmitsSNIWithoutProcess(t *testing.T) {
	// 프로세스를 못 찾았다고 이벤트를 버리면 어느 도메인에 접속했는지까지 잃는다.
	s, src := newTestSensor(&fakeOwner{byPort: map[int]string{}})
	frame := ipv4Frame(testSrcIP, testDstIP,
		tcpSegment(testSrcPrt, 443, clientHello(t, "example.com")))

	got := runSensor(t, s, src, frame)
	if len(got) != 1 {
		t.Fatalf("이벤트 %d 개: %+v", len(got), got)
	}
	if got[0].Domain != "example.com" {
		t.Errorf("도메인 = %q", got[0].Domain)
	}
	if got[0].Process != "" {
		t.Errorf("프로세스 = %q, 비어 있어야 한다", got[0].Process)
	}
}

func TestL7SensorJoinsSplitClientHello(t *testing.T) {
	// 요즘 ClientHello 는 MTU 를 넘어 두 세그먼트로 쪼개지는 일이 흔하다.
	s, src := newTestSensor(nil)
	hello := clientHello(t, "split.example.com")
	if len(hello) < 200 {
		t.Fatalf("ClientHello 가 %d 바이트뿐이라 쪼개는 의미가 없다", len(hello))
	}
	cut := len(hello) / 2

	got := runSensor(t, s, src,
		ipv4Frame(testSrcIP, testDstIP, tcpSegment(testSrcPrt, 443, hello[:cut])),
		ipv4Frame(testSrcIP, testDstIP, tcpSegment(testSrcPrt, 443, hello[cut:])),
	)
	if len(got) != 1 {
		t.Fatalf("이벤트 %d 개, 원하는 값 1개: %+v", len(got), got)
	}
	if got[0].Domain != "split.example.com" {
		t.Errorf("도메인 = %q", got[0].Domain)
	}
}

func TestL7SensorDoesNotRepeatSNI(t *testing.T) {
	// TCP 재전송으로 같은 ClientHello 가 두 번 올 수 있다. 같은 흐름에서 두 번 내면 안 된다.
	s, src := newTestSensor(nil)
	hello := clientHello(t, "once.example.com")
	frame := ipv4Frame(testSrcIP, testDstIP, tcpSegment(testSrcPrt, 443, hello))

	got := runSensor(t, s, src, frame, frame)
	if len(got) != 1 {
		t.Fatalf("이벤트 %d 개, 원하는 값 1개: %+v", len(got), got)
	}
}

func TestL7SensorSurvivesGarbage(t *testing.T) {
	// 신뢰할 수 없는 입력이다. 깨진 패킷 한 장이 센서를 죽이면 그 뒤 관측이 통째로 사라진다.
	s, src := newTestSensor(nil)
	good := ipv4Frame(testResIP, testSrcIP,
		udpSegment(53, testSrcPrt, dnsResponse(t, "after.example.com", dnsmessage.TypeA, "1.2.3.4")))

	got := runSensor(t, s, src,
		nil,
		[]byte{},
		[]byte{0xff},
		make([]byte, 14),
		ipv4Frame(testResIP, testSrcIP, udpSegment(53, testSrcPrt, []byte{0x00, 0x01, 0x02})),
		ipv4Frame(testSrcIP, testDstIP, tcpSegment(testSrcPrt, 443, []byte{22, 3, 1, 0xff, 0xff, 0x01})),
		good,
	)
	if len(got) != 1 {
		t.Fatalf("이벤트 %d 개, 원하는 값 1개: %+v", len(got), got)
	}
	if got[0].Domain != "after.example.com" {
		t.Errorf("도메인 = %q", got[0].Domain)
	}
}

func TestL7SensorIgnoresUnrelatedTraffic(t *testing.T) {
	// 필터가 커널에서 거르지만 인터페이스를 공유하는 다른 캡처가 섞여 들어올 수 있다.
	s, src := newTestSensor(nil)
	got := runSensor(t, s, src,
		// Host 가 없어 어느 도메인에 갔는지 말해 주지 않는 요청. 목적지 IP 는 network 이벤트에 있다.
		ipv4Frame(testSrcIP, testDstIP, tcpSegment(testSrcPrt, 80, []byte("GET / HTTP/1.1\r\n\r\n"))),
		ipv4Frame(testSrcIP, testResIP, udpSegment(testSrcPrt, 123, make([]byte, 48))),
		// 443 에서 들어오는 쪽. ServerHello 는 SNI 를 담지 않는다.
		ipv4Frame(testDstIP, testSrcIP, tcpSegment(443, testSrcPrt, clientHello(t, "wrong.example.com"))),
	)
	if len(got) != 0 {
		t.Fatalf("이벤트가 %d 개 나왔다: %+v", len(got), got)
	}
}

func TestL7SensorClosesSourceOnCancel(t *testing.T) {
	s, src := newTestSensor(nil)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, make(chan event.Event, 1)) }()

	cancel()
	select {
	case err := <-done:
		if !errorIsCanceled(err) {
			t.Errorf("Run 반환값 = %v, context.Canceled 여야 한다", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ctx 를 끊었는데 Run 이 안 돌아온다")
	}
	if !src.isClosed() {
		t.Error("캡처가 닫히지 않았다. BPF 장치가 물린 채로 남는다")
	}
}

func TestL7SensorReportsCaptureDeath(t *testing.T) {
	// 캡처가 혼자 죽으면 조용히 0 건이 되면 안 된다. 런타임이 로그에 남길 수 있게 오류로 올린다.
	s, src := newTestSensor(nil)
	done := make(chan error, 1)
	go func() { done <- s.Run(context.Background(), make(chan event.Event, 1)) }()

	close(src.ch)
	select {
	case err := <-done:
		if err == nil {
			t.Error("캡처가 끝났는데 오류가 안 났다")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("캡처 채널을 닫았는데 Run 이 안 돌아온다")
	}
}

func errorIsCanceled(err error) bool { return err == context.Canceled }

func decodeDetail(t *testing.T, raw string) map[string]any {
	t.Helper()
	if raw == "" {
		return map[string]any{}
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("detail 이 JSON 이 아니다: %v (%q)", err, raw)
	}
	return out
}

// --- 합성 페이로드 만들기 ---

// dnsQuery 는 진짜 DNS 질의 바이트를 만든다.
func dnsQuery(t *testing.T, domain string, qtype dnsmessage.Type) []byte {
	t.Helper()
	return packDNS(t, dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 0x1234},
		Questions: []dnsmessage.Question{question(t, domain, qtype)},
	})
}

// dnsResponse 는 진짜 DNS 응답 바이트를 만든다. answers 가 비면 NXDOMAIN 같은 빈 응답이 된다.
func dnsResponse(t *testing.T, domain string, qtype dnsmessage.Type, answers ...string) []byte {
	t.Helper()
	q := question(t, domain, qtype)
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 0x1234, Response: true},
		Questions: []dnsmessage.Question{q},
	}
	for _, ip := range answers {
		var a dnsmessage.AResource
		copy(a.A[:], net.ParseIP(ip).To4())
		msg.Answers = append(msg.Answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
			Body:   &a,
		})
	}
	return packDNS(t, msg)
}

func question(t *testing.T, domain string, qtype dnsmessage.Type) dnsmessage.Question {
	t.Helper()
	name, err := dnsmessage.NewName(domain + ".")
	if err != nil {
		t.Fatalf("dnsmessage.NewName: %v", err)
	}
	return dnsmessage.Question{Name: name, Type: qtype, Class: dnsmessage.ClassINET}
}

func packDNS(t *testing.T, msg dnsmessage.Message) []byte {
	t.Helper()
	raw, err := msg.Pack()
	if err != nil {
		t.Fatalf("DNS 메시지를 만들지 못했다: %v", err)
	}
	return raw
}

// clientHello 는 crypto/tls 가 실제로 보내는 ClientHello 바이트를 그대로 가져온다.
//
// 손으로 TLS 레코드를 짜지 않는 이유는, 손으로 짠 것은 우리가 파서에 맞춰 만든 것이라
// 파서가 진짜 클라이언트의 ClientHello 를 못 읽어도 테스트가 통과하기 때문이다.
// net.Pipe 는 동기라 핸드셰이크가 첫 레코드를 쓰는 순간 그대로 읽힌다.
func clientHello(t *testing.T, sni string) []byte {
	t.Helper()

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		// 상대가 응답하지 않으므로 핸드셰이크는 실패한다. 첫 레코드만 필요하다.
		// NextProtos 를 주는 이유는 브라우저가 늘 ALPN 을 보내기 때문이다. 안 주면 우리가
		// 실제로 만날 일 없는 모양의 ClientHello 로 테스트하게 된다.
		_ = tls.Client(client, &tls.Config{
			ServerName: sni,
			NextProtos: []string{"h2", "http/1.1"},
		}).Handshake()
	}()

	if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 8192)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("ClientHello 를 읽지 못했다: %v", err)
	}
	return buf[:n]
}

// 평문 HTTP 도 수집한다. TLS 만 보면 암호화되지 않은 통신을 통째로 놓친다.
func TestL7SensorEmitsHTTPRequest(t *testing.T) {
	owner := &fakeOwner{byPort: map[int]string{testSrcPrt: "/usr/bin/curl"}}
	s, src := newTestSensor(owner)

	req := "GET /admin/panel?token=secret123#frag HTTP/1.1\r\n" +
		"Host: internal.example.com\r\n" +
		"User-Agent: curl/8.4.0\r\n" +
		"Authorization: Bearer supersecret\r\n" +
		"Cookie: session=abc\r\n\r\n"
	frame := ipv4Frame(testSrcIP, testDstIP, tcpSegment(testSrcPrt, 80, []byte(req)))

	got := runSensor(t, s, src, frame)
	if len(got) != 1 {
		t.Fatalf("이벤트 %d 개: %+v", len(got), got)
	}

	e := got[0]
	if e.Type != event.TypeL7 {
		t.Errorf("타입 = %q, want %q", e.Type, event.TypeL7)
	}
	// 도메인 자리에는 Host 가 온다. TLS 의 SNI 와 같은 뜻이라 한 컬럼으로 조회된다.
	if e.Domain != "internal.example.com" {
		t.Errorf("도메인 = %q", e.Domain)
	}
	if e.Process != "curl" {
		t.Errorf("프로세스 = %q", e.Process)
	}
	if e.DestPort != 80 {
		t.Errorf("목적지 포트 = %d", e.DestPort)
	}

	detail := decodeDetail(t, e.Detail)
	if detail["l7Protocol"] != "HTTP" {
		t.Errorf("l7Protocol = %v, want HTTP", detail["l7Protocol"])
	}
	if detail["httpMethod"] != "GET" {
		t.Errorf("httpMethod = %v", detail["httpMethod"])
	}
	if detail["httpUserAgent"] != "curl/8.4.0" {
		t.Errorf("httpUserAgent = %v", detail["httpUserAgent"])
	}

	// 질의 문자열에는 토큰과 세션 값이 흔히 들어간다. 그걸 서버로 옮기면 수집이 아니라 감시다.
	path, _ := detail["httpPath"].(string)
	if path != "/admin/panel" {
		t.Errorf("httpPath = %q, 질의 문자열이 떨어져야 한다", path)
	}
	// 자격증명 헤더는 애초에 읽지 않는다. detail 어디에도 남으면 안 된다.
	if strings.Contains(e.Detail, "supersecret") || strings.Contains(e.Detail, "session=abc") {
		t.Errorf("자격증명이 새어 나갔다: %s", e.Detail)
	}
}

func TestL7SensorEmitsHTTPResponse(t *testing.T) {
	// 응답의 상태 코드는 조사에 쓸모가 있다. 출발지 80 도 받는 이유다.
	s, src := newTestSensor(&fakeOwner{byPort: map[int]string{}})
	resp := "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n"
	frame := ipv4Frame(testDstIP, testSrcIP, tcpSegment(80, testSrcPrt, []byte(resp)))

	got := runSensor(t, s, src, frame)
	if len(got) != 1 {
		t.Fatalf("이벤트 %d 개: %+v", len(got), got)
	}
	detail := decodeDetail(t, got[0].Detail)
	if detail["httpStatusCode"] != float64(404) {
		t.Errorf("httpStatusCode = %v", detail["httpStatusCode"])
	}
}

// TLS 이벤트에도 어느 프로토콜인지 표시가 있어야 HTTP 와 구분된다.
func TestL7SensorMarksTLSProtocol(t *testing.T) {
	s, src := newTestSensor(&fakeOwner{byPort: map[int]string{}})
	frame := ipv4Frame(testSrcIP, testDstIP,
		tcpSegment(testSrcPrt, 443, clientHello(t, "example.com")))

	got := runSensor(t, s, src, frame)
	if len(got) != 1 {
		t.Fatalf("이벤트 %d 개", len(got))
	}
	if detail := decodeDetail(t, got[0].Detail); detail["l7Protocol"] != "TLS" {
		t.Errorf("l7Protocol = %v, want TLS", detail["l7Protocol"])
	}
}

// 80 번이라고 아무 바이트나 HTTP 로 보면 안 된다.
func TestL7SensorIgnoresNonHTTPOnPort80(t *testing.T) {
	s, src := newTestSensor(&fakeOwner{byPort: map[int]string{}})
	frame := ipv4Frame(testSrcIP, testDstIP,
		tcpSegment(testSrcPrt, 80, []byte{0x16, 0x03, 0x01, 0x00, 0x05, 1, 2, 3, 4, 5}))

	if got := runSensor(t, s, src, frame); len(got) != 0 {
		t.Errorf("HTTP 가 아닌데 이벤트 %d 개: %+v", len(got), got)
	}
}
