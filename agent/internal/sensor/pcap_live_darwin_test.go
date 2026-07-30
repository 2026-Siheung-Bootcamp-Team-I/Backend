//go:build darwin

package sensor

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/event"
	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/packet"
)

// 이 파일은 실제 BPF 캡처를 실기기에서 확인하는 opt-in 테스트다.
//
// # 왜 기본으로 안 도나
//
// root 가 있어야 하고(/dev/bpf* 는 crw------- root:wheel 이다) 실제 네트워크가 나가야 한다.
// 둘 다 CI 나 보통의 `go test ./...` 에서는 만족되지 않는다. 그래서 EDRDOG_LIVE 가 없으면
// 건너뛴다. 나머지 테스트는 전부 가짜 소스로 돌기 때문에 이것 하나만 환경을 탄다.
//
// # 어떻게 돌리나
//
//	cd agent
//	go test -c -o /tmp/sensor.test ./internal/sensor
//	sudo EDRDOG_LIVE=1 /tmp/sensor.test -test.run TestLiveCapture -test.v
//
// 테스트 바이너리를 먼저 만들고 그걸 sudo 로 돌리는 이유는, `sudo go test` 가 root 의
// PATH 와 빌드 캐시를 쓰기 때문이다. 컴파일은 사용자 권한으로 하고 실행만 root 로 한다.
//
// 시간을 늘리려면 EDRDOG_LIVE_SECONDS 를 준다(기본 30초).
//
// # 무엇을 보나
//
// 트래픽은 테스트가 직접 만든다. 사람이 브라우저를 여는 것에 기대면 아무것도 안 나왔을 때
// 캡처가 고장난 것인지 트래픽이 없었던 것인지 구분할 수 없다. 그래서 이 테스트는 스스로
// DNS 질의와 TLS 접속을 낸 뒤, 그것이 이벤트로 돌아오는지 본다. 확인 항목 셋:
//
//  1. dns 이벤트의 domain 이 우리가 물어본 이름이고 detail 이 차 있는가.
//     안 나오면 BPF 필터의 UDP 53 양방향 판정이나 bpf_hdr 쪼개기가 틀린 것이다.
//  2. l7 이벤트의 domain 이 우리가 접속한 SNI 인가.
//     안 나오면 필터의 TCP 443 조건이나 Assembler 배선이 틀린 것이다.
//  3. l7 이벤트의 process 가 비어 있지 않은가.
//     이 테스트 바이너리 자신이 접속하므로 반드시 찾혀야 한다. 비면 ProcOwner 의 libproc
//     조회(insi_lport 를 로컬 포트로 읽는 부분)가 틀린 것이다.
//
// 시작 로그의 buffer 값도 같이 본다. 524288 이어야 커널 버퍼 확대가 먹은 것이다.
// 4096 이면 기본값 그대로라 부하가 걸릴 때 패킷을 크게 잃는다.
//
// 여러 패킷이 한 read 에 담겨야 bpf_hdr 쪼개기가 실제로 검증된다. 그래서 접속을 여러 번 낸다.

// liveHosts 는 트래픽을 낼 대상이다. 여러 개를 쓰는 이유는 한 곳이 죽어 있어도 검증이 되게 하려는 것이다.
var liveHosts = []string{"example.com", "www.cloudflare.com", "go.dev"}

// liveHTTPHost 는 평문 HTTP 로 접속할 대상이다.
//
// 요즘은 대부분 HTTPS 로 넘겨 버리는데, 그 넘김(301) 자체가 평문 요청과 응답이라 우리가
// 확인하려는 것은 그대로 잡힌다. 오히려 상태 코드까지 같이 검증된다.
const liveHTTPHost = "example.com"

func TestLiveCapture(t *testing.T) {
	if os.Getenv("EDRDOG_LIVE") == "" {
		t.Skip("EDRDOG_LIVE 가 없다. 실기기 캡처 확인은 opt-in 이다. 이 파일 위쪽 주석에 실행법이 있다")
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	capture, err := OpenCapture(log)
	if err != nil {
		t.Fatalf("캡처를 열지 못했다: %v\n\nroot 로 돌리고 있는지, 기본 경로가 이더넷 인터페이스인지 확인해라", err)
	}

	s := &L7Sensor{
		Factory:  event.Factory{Host: "live"},
		Source:   capture,
		Owner:    NewProcOwner(),
		LinkType: packet.LinkEthernet,
		Logger:   log,
	}

	ctx, cancel := context.WithTimeout(context.Background(), liveDuration(t))
	defer cancel()

	out := make(chan event.Event, 4096)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := s.Run(ctx, out); err != nil && ctx.Err() == nil {
			t.Errorf("센서가 멈췄다: %v", err)
		}
	}()

	// 캡처가 인터페이스에 붙을 틈을 준 뒤 트래픽을 낸다.
	probe := make(chan liveProbe, 1)
	go func() {
		time.Sleep(500 * time.Millisecond)
		probe <- generateLiveTraffic(t, log)
	}()

	var (
		dnsEvents []event.Event
		l7Events  []event.Event
		want      liveProbe
		gotProbe  bool
	)
	for collecting := true; collecting; {
		select {
		case e := <-out:
			raw, _ := json.Marshal(e)
			t.Log(string(raw))
			if e.Type == event.TypeDNS {
				dnsEvents = append(dnsEvents, e)
			} else {
				l7Events = append(l7Events, e)
			}
		case want = <-probe:
			gotProbe = true
		case <-done:
			collecting = false
		}
	}

	// 센서가 멈춘 뒤에도 채널에 남은 것이 있다. 그것까지 세지 않으면 마지막 몇 건을 놓친다.
	for drained := false; !drained; {
		select {
		case e := <-out:
			raw, _ := json.Marshal(e)
			t.Log(string(raw))
			if e.Type == event.TypeDNS {
				dnsEvents = append(dnsEvents, e)
			} else {
				l7Events = append(l7Events, e)
			}
		default:
			drained = true
		}
	}
	if !gotProbe {
		select {
		case want = <-probe:
		default:
		}
	}
	t.Logf("수집 결과: dns=%d l7=%d (질의한 이름 %q, 접속한 SNI %v)",
		len(dnsEvents), len(l7Events), want.dnsName, want.sniHosts)

	if len(want.sniHosts) == 0 {
		t.Skip("트래픽을 하나도 못 냈다. 네트워크가 없는 환경으로 보고 건너뛴다")
	}

	// 1. DNS
	if len(dnsEvents) == 0 {
		t.Error("dns 이벤트가 0건이다. BPF 필터의 UDP 53 판정이나 bpf_hdr 쪼개기를 의심해라")
	} else if !anyDomain(dnsEvents, want.dnsName) {
		t.Errorf("우리가 물어본 %q 가 dns 이벤트에 없다. 다른 도메인만 잡혔다면 필터는 살아 있고 응답 파싱이 문제다", want.dnsName)
	}
	for _, e := range dnsEvents {
		if e.Domain == "" {
			t.Error("domain 이 빈 dns 이벤트가 있다")
		}
		if e.Process != "" {
			t.Errorf("dns 이벤트에 프로세스가 붙었다(%q). macOS 에서는 mDNSResponder 만 나오므로 비워야 한다", e.Process)
		}
	}

	// 2. TLS SNI
	if len(l7Events) == 0 {
		t.Error("l7 이벤트가 0건이다. BPF 필터의 TCP 443 판정이나 Assembler 배선을 의심해라")
	}
	matched := false
	for _, host := range want.sniHosts {
		if anyDomain(l7Events, host) {
			matched = true
			break
		}
	}
	if len(l7Events) > 0 && !matched {
		t.Errorf("우리가 접속한 SNI %v 가 l7 이벤트에 없다", want.sniHosts)
	}

	// 3. 프로세스 귀속. 접속을 낸 것이 이 테스트 바이너리라 반드시 찾혀야 한다.
	withProcess := 0
	for _, e := range l7Events {
		if e.Process != "" {
			withProcess++
		}
	}
	if len(l7Events) > 0 && withProcess == 0 {
		t.Error("l7 이벤트에 프로세스가 하나도 안 붙었다. ProcOwner 의 libproc 조회를 의심해라")
	}
	t.Logf("프로세스가 붙은 l7 이벤트: %d/%d", withProcess, len(l7Events))

	// 4. 평문 HTTP. TLS 만 확인하면 포트 80 경로가 도는지 알 수 없다.
	if want.httpHost != "" {
		var httpEvents []event.Event
		for _, e := range l7Events {
			if d := liveDetail(t, e); d["l7Protocol"] == "HTTP" {
				httpEvents = append(httpEvents, e)
			}
		}
		if len(httpEvents) == 0 {
			t.Errorf("HTTP 이벤트가 0건이다. BPF 필터의 포트 80 판정이나 ParseHTTP 배선을 의심해라 (%s 에 요청했다)", want.httpHost)
		}
		for _, e := range httpEvents {
			d := liveDetail(t, e)
			t.Logf("HTTP: host=%q method=%v path=%v status=%v process=%q",
				e.Domain, d["httpMethod"], d["httpPath"], d["httpStatusCode"], e.Process)
		}
	}
}

// liveProbe 는 테스트가 실제로 낸 트래픽이다. 이 값과 잡힌 이벤트를 맞춰 본다.
type liveProbe struct {
	dnsName  string   // 질의한 이름
	sniHosts []string // 접속에 성공한 호스트
	httpHost string   // 평문 HTTP 로 접속한 호스트. 실패했으면 빈 값
}

// generateLiveTraffic 은 확인에 쓸 DNS 질의와 TLS 접속을 낸다.
//
// DNS 이름에 난수를 섞는 이유는 캐시 때문이다. 이미 물어본 이름은 mDNSResponder 가 캐시에서
// 답해 버려 패킷이 아예 안 나가고, 그러면 캡처가 멀쩡해도 dns 이벤트가 0건이 된다.
// 없는 이름이라 NXDOMAIN 이 오지만 그것도 응답이라 이벤트로 잡힌다.
func generateLiveTraffic(t *testing.T, log *slog.Logger) liveProbe {
	t.Helper()

	var buf [6]byte
	rand.Read(buf[:])
	probe := liveProbe{dnsName: "edrdog-" + hex.EncodeToString(buf[:]) + ".example.com"}

	if _, err := net.LookupHost(probe.dnsName); err != nil {
		// NXDOMAIN 이면 여기서 오류가 난다. 질의 패킷은 이미 나갔으므로 정상 경로다.
		log.Debug("DNS 질의를 냈다", "name", probe.dnsName, "err", err)
	}

	// 접속을 여러 번 내야 여러 패킷이 한 read 에 담기고, 그래야 bpf_hdr 쪼개기가 검증된다.
	for _, host := range liveHosts {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", host+":443", &tls.Config{
			ServerName: host,
			NextProtos: []string{"h2", "http/1.1"},
		})
		if err != nil {
			log.Warn("TLS 접속 실패. 이 호스트는 건너뛴다", "host", host, "err", err)
			continue
		}
		conn.Close()
		probe.sniHosts = append(probe.sniHosts, host)
	}

	// 평문 HTTP 도 한 번 낸다. TLS 만 확인하면 포트 80 경로가 도는지 알 수 없다.
	if resp, err := (&http.Client{Timeout: 5 * time.Second}).Get("http://" + liveHTTPHost + "/"); err != nil {
		log.Warn("HTTP 요청 실패. 그 확인은 건너뛴다", "host", liveHTTPHost, "err", err)
	} else {
		resp.Body.Close()
		probe.httpHost = liveHTTPHost
	}
	return probe
}

// liveDuration 은 얼마나 캡처할지다.
func liveDuration(t *testing.T) time.Duration {
	t.Helper()
	if raw := os.Getenv("EDRDOG_LIVE_SECONDS"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			t.Fatalf("EDRDOG_LIVE_SECONDS 가 %q 다. 양의 정수여야 한다", raw)
		}
		return time.Duration(n) * time.Second
	}
	return 30 * time.Second
}

func anyDomain(events []event.Event, domain string) bool {
	for _, e := range events {
		if e.Domain == domain {
			return true
		}
	}
	return false
}

// liveDetail 은 이벤트의 detail JSON 을 푼다. 못 풀면 빈 맵이라 호출부가 nil 검사를 안 해도 된다.
func liveDetail(t *testing.T, e event.Event) map[string]any {
	t.Helper()
	if e.Detail == "" {
		return map[string]any{}
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(e.Detail), &out); err != nil {
		t.Errorf("detail 이 JSON 이 아니다: %v (%s)", err, e.Detail)
		return map[string]any{}
	}
	return out
}
