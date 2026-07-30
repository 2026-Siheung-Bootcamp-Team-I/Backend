//go:build windows

package sensor

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/event"
	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/packet"
)

// 이 파일은 Windows 실기기에서만 도는 opt-in 테스트다.
//
// # 왜 기본으로 안 도나
//
// 관리자 권한이 있어야 하고(ETW 세션 생성과 pktmon 둘 다), 실제 네트워크가 나가야 하며,
// 다른 도구가 pktmon 캡처를 쓰고 있지 않아야 한다. 셋 다 보통의 `go test ./...` 에서는
// 만족되지 않는다. EDRDOG_LIVE 가 없으면 건너뛴다.
//
// # 어떻게 돌리나
//
// 관리자 PowerShell 에서:
//
//	cd agent
//	go test -c -o C:\Temp\sensor.test.exe .\internal\sensor
//	$env:EDRDOG_LIVE=1; C:\Temp\sensor.test.exe -test.run TestLivePktMonCapture -test.v
//
// 시간을 늘리려면 EDRDOG_LIVE_SECONDS 를 준다(기본 45초).
//
// # 이 테스트가 단언하는 것
//
// 트래픽은 테스트가 직접 만든다. 사람이 브라우저를 여는 것에 기대면 아무것도 안 나왔을 때
// 캡처가 고장난 것인지 트래픽이 없었던 것인지 구분할 수 없다.
//
//  1. l7 이벤트가 한 건이라도 나오는가. 안 나오면 아래 넷 중 하나다. 어느 것인지는 로그의
//     pktmon 상태 줄(accept/short/sizeMismatch/empty/linkType/inbound)이 말해 준다.
//     - pktmon 드라이버가 안 돌아 이벤트 자체가 없다(전부 0)
//     - keyword 0x10 이 안 걸려 프레임 바이트가 없다(empty 가 쌓임)
//     - 우리가 읽는 필드 위치가 이 Windows 판과 어긋났다(sizeMismatch 가 쌓임)
//     - 프레임이 이더넷도 raw IP 도 아니다(linkType 이 쌓임)
//  2. 우리가 접속한 SNI 가 그 이벤트에 들어 있는가. 다른 도메인만 잡혔다면 캡처는 살아
//     있고 필터나 조립 쪽이 문제다.
//  3. l7 이벤트에 프로세스가 붙는가. 접속을 낸 것이 이 테스트 바이너리 자신이므로 반드시
//     붙어야 한다. 하나도 안 붙으면 Kernel-Network 연결 이벤트를 못 받았거나
//     FlowOwners 의 조인 키(sport/daddr/dport)가 어긋난 것이다.
//  4. dns 이벤트가 이 경로로 나오지 않는가. Windows 의 DNS 는 ETW 로 따로 받으므로
//     패킷에서 또 뽑으면 같은 질의가 두 번 올라간다. 그것을 커널 필터로 막았는지 본다.
//
// 실기기에서 사람이 눈으로 확인할 것은 README 의 "Windows 실기기 검증 절차" 에 적어 두었다.
// 특히 프레임이 이더넷인지 IP 헤더부터인지는 로그의 packetType1 / packetType3 으로 갈린다.

// pktMonLiveHosts 는 트래픽을 낼 대상이다. 한 곳이 죽어 있어도 검증이 되게 여럿을 쓴다.
var pktMonLiveHosts = []string{"example.com", "www.cloudflare.com", "go.dev"}

func TestLivePktMonCapture(t *testing.T) {
	if os.Getenv("EDRDOG_LIVE") == "" {
		t.Skip("EDRDOG_LIVE 가 없다. 실기기 캡처 확인은 opt-in 이다. 이 파일 위쪽 주석에 실행법이 있다")
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	capture, err := OpenPktMonCapture(log)
	if err != nil {
		t.Fatalf("pktmon 캡처를 열지 못했다: %v\n\n"+
			"관리자 권한으로 돌리고 있는지, `pktmon status` 로 다른 캡처가 돌고 있지 않은지,\n"+
			"Windows Defender 가 pktmon 조작을 막고 있지 않은지 확인해라", err)
	}

	flows := NewFlowOwners()
	etwSensor := &ETWSensor{
		Factory: event.Factory{Host: "live"},
		// 연결 이벤트만 있으면 된다. 파일과 프로세스까지 켜면 로그가 그쪽으로 뒤덮인다.
		Sensors: map[string]bool{"network": true},
		Logger:  log,
		PktMon:  capture,
		Flows:   flows,
	}
	l7Sensor := &L7Sensor{
		Factory:  event.Factory{Host: "live"},
		Source:   capture,
		Owner:    flows,
		LinkType: packet.LinkEthernet,
		Logger:   log,
	}

	ctx, cancel := context.WithTimeout(context.Background(), pktMonLiveDuration(t))
	defer cancel()

	out := make(chan event.Event, 4096)
	etwDone := make(chan error, 1)
	go func() { etwDone <- etwSensor.Run(ctx, out) }()

	l7Done := make(chan struct{})
	go func() {
		defer close(l7Done)
		if err := l7Sensor.Run(ctx, out); err != nil && ctx.Err() == nil {
			t.Errorf("l7 센서가 멈췄다: %v", err)
		}
	}()

	// 세션이 붙을 틈을 준 뒤 트래픽을 낸다.
	probe := make(chan []string, 1)
	go func() {
		time.Sleep(2 * time.Second)
		probe <- generatePktMonLiveTraffic(t, log)
	}()

	var (
		l7Events  []event.Event
		dnsEvents []event.Event
		wantSNI   []string
	)
	for collecting := true; collecting; {
		select {
		case e := <-out:
			raw, _ := json.Marshal(e)
			t.Log(string(raw))
			switch e.Type {
			case event.TypeL7:
				l7Events = append(l7Events, e)
			case event.TypeDNS:
				dnsEvents = append(dnsEvents, e)
			}
		case hosts := <-probe:
			wantSNI = hosts
		case <-l7Done:
			collecting = false
		}
	}
	<-etwDone

	// 센서가 멈춘 뒤에도 채널에 남은 것이 있다.
	for drained := false; !drained; {
		select {
		case e := <-out:
			raw, _ := json.Marshal(e)
			t.Log(string(raw))
			switch e.Type {
			case event.TypeL7:
				l7Events = append(l7Events, e)
			case event.TypeDNS:
				dnsEvents = append(dnsEvents, e)
			}
		default:
			drained = true
		}
	}
	if len(wantSNI) == 0 {
		select {
		case wantSNI = <-probe:
		default:
		}
	}

	capture.ReportHealth()
	hits, misses := flows.Stats()
	t.Logf("수집 결과: l7=%d dns=%d, 접속한 SNI %v, 흐름 조인 hit=%d miss=%d",
		len(l7Events), len(dnsEvents), wantSNI, hits, misses)

	if len(wantSNI) == 0 {
		t.Skip("TLS 접속을 하나도 못 냈다. 네트워크가 없는 환경으로 보고 건너뛴다")
	}

	// 1. SNI 가 잡히는가.
	if len(l7Events) == 0 {
		t.Error("l7 이벤트가 0건이다. 위 pktmon 상태 줄의 이유별 건수를 보고 원인을 좁혀라")
	}

	// 2. 우리가 접속한 SNI 인가.
	matched := false
	for _, host := range wantSNI {
		for _, e := range l7Events {
			if e.Domain == host {
				matched = true
			}
		}
	}
	if len(l7Events) > 0 && !matched {
		t.Errorf("우리가 접속한 SNI %v 가 l7 이벤트에 없다. 잡힌 도메인은 다른 것들이다", wantSNI)
	}

	// 3. 프로세스가 붙는가. 접속을 낸 것이 이 테스트 바이너리라 반드시 붙어야 한다.
	withProcess := 0
	for _, e := range l7Events {
		if e.Process != "" {
			withProcess++
		}
	}
	if len(l7Events) > 0 && withProcess == 0 {
		t.Error("l7 이벤트에 프로세스가 하나도 안 붙었다. " +
			"Kernel-Network 연결 이벤트를 못 받았거나 FlowOwners 의 조인 키가 어긋난 것이다")
	}
	t.Logf("프로세스가 붙은 l7 이벤트: %d/%d", withProcess, len(l7Events))

	// 4. 패킷에서 DNS 를 또 뽑지 않는가.
	//
	// 이 테스트에서는 ETW 의 dns 센서를 끄고 돌리므로, 여기 dns 이벤트가 있다면 그건 반드시
	// 패킷 경로에서 나온 것이다. 커널 필터가 TCP 443 만 통과시키므로 0건이어야 한다.
	if len(dnsEvents) > 0 {
		t.Errorf("패킷에서 dns 이벤트가 %d 건 나왔다. pktmon 필터에 53 번이 남아 있는 것 같다. "+
			"이대로 두면 Windows 에서 같은 질의가 ETW 와 패킷 양쪽으로 두 번 올라간다", len(dnsEvents))
	}
}

// generatePktMonLiveTraffic 은 확인에 쓸 TLS 접속을 낸다. 접속에 성공한 호스트를 돌려준다.
//
// DNS 질의는 일부러 내지 않는다. 이 테스트의 dns 이벤트 0건 단언이 "질의가 없어서 0건" 이
// 아니라 "필터가 막아서 0건" 이어야 하기 때문인데, TLS 접속을 하면 이름 해석이 반드시
// 일어나므로 질의 자체는 어차피 나간다.
func generatePktMonLiveTraffic(t *testing.T, log *slog.Logger) []string {
	t.Helper()

	var ok []string
	for _, host := range pktMonLiveHosts {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", host+":443", &tls.Config{
			ServerName: host,
			NextProtos: []string{"h2", "http/1.1"},
		})
		if err != nil {
			log.Warn("TLS 접속 실패. 이 호스트는 건너뛴다", "host", host, "err", err)
			continue
		}
		conn.Close()
		ok = append(ok, host)
	}
	return ok
}

// pktMonLiveDuration 은 얼마나 캡처할지다.
//
// macOS 쪽(30초)보다 길게 잡는다. ETW 실시간 세션은 버퍼를 기본 1초 주기로 비우고,
// pktmon 은 시작한 뒤 드라이버가 올라오는 데 시간이 더 걸린다.
func pktMonLiveDuration(t *testing.T) time.Duration {
	t.Helper()
	if raw := os.Getenv("EDRDOG_LIVE_SECONDS"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			t.Fatalf("EDRDOG_LIVE_SECONDS 가 %q 다. 양의 정수여야 한다", raw)
		}
		return time.Duration(n) * time.Second
	}
	return 45 * time.Second
}
