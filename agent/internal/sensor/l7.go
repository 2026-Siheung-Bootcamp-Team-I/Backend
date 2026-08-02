package sensor

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/event"
	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/packet"
)

// PacketSource 는 캡처한 프레임을 흘려보낸다. 플랫폼별 캡처 구현이 이걸 만족한다.
type PacketSource interface {
	// Packets 는 캡처한 프레임을 준다. 채널이 닫히면 캡처가 끝난 것이다.
	Packets() <-chan []byte
	Close() error
}

// SocketOwner 는 흐름의 주인 프로세스를 찾는다.
type SocketOwner interface {
	// Lookup 은 로컬 포트로 프로세스 실행 경로를 찾는다. 못 찾으면 빈 문자열이다.
	Lookup(localPort int, remoteIP string, remotePort int) string
}

// L7Sensor 는 캡처한 패킷에서 DNS 응답과 TLS SNI 를 뽑아 dns 와 l7 이벤트로 만든다.
type L7Sensor struct {
	Factory  event.Factory
	Source   PacketSource
	Owner    SocketOwner // nil 이면 프로세스를 붙이지 않는다
	LinkType packet.LinkType
	Logger   *slog.Logger
}

// Name 은 센서 이름이다.
func (s *L7Sensor) Name() string { return "l7" }

// Run 은 캡처가 주는 프레임을 이벤트로 바꿔 내보낸다.
// ctx 가 끝나면 캡처를 닫고 돌아온다.
func (s *L7Sensor) Run(ctx context.Context, out chan<- event.Event) error {
	defer s.Source.Close()

	assembler := packet.NewAssembler()
	packets := s.Source.Packets()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case frame, ok := <-packets:
			if !ok {
				// 정상 종료면 ctx 가 이미 끝나 있다. 아니면 캡처가 혼자 죽은 것이라 알려야 한다.
				if err := ctx.Err(); err != nil {
					return err
				}
				return errors.New("패킷 캡처가 예기치 않게 끝났다")
			}
			e, ok := s.handle(frame, assembler, time.Now())
			if !ok {
				continue
			}
			select {
			case out <- e:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}

// handle 은 프레임 하나에서 이벤트를 뽑는다. 뽑을 것이 없으면 두 번째 값이 false 다.
// recover 를 빼면 packet 파싱이 panic 하는 날 패킷 한 장 대신 에이전트가 통째로 죽는다.
func (s *L7Sensor) handle(frame []byte, assembler *packet.Assembler, now time.Time) (e event.Event, ok bool) {
	defer func() {
		if r := recover(); r != nil {
			s.log().Error("패킷 파싱이 panic 했다. 이 패킷만 버린다", "sensor", s.Name(), "panic", r)
			e, ok = event.Event{}, false
		}
	}()

	flow, payload, ok := packet.Parse(frame, s.LinkType)
	if !ok {
		return event.Event{}, false
	}
	switch {
	case flow.Protocol == "udp" && (flow.SrcPort == portDNS || flow.DstPort == portDNS):
		return s.dnsEvent(flow, payload, now)
	case flow.Protocol == "tcp" && flow.DstPort == portHTTPS:
		return s.tlsEvent(flow, payload, assembler, now)
	case flow.Protocol == "tcp" && (flow.DstPort == portHTTP || flow.SrcPort == portHTTP):
		return s.httpEvent(flow, payload, now)
	}
	return event.Event{}, false
}

// dnsEvent 는 DNS 응답에서 이벤트를 만든다.
// 질의(IsResponse=false)도 내보내면 같은 도메인이 대시보드에 두 번 올라간다.
// 프로세스는 일부러 안 붙인다. macOS 질의는 전부 mDNSResponder 를 거쳐 그 주인이 질의자가 아니다.
func (s *L7Sensor) dnsEvent(flow packet.Flow, payload []byte, now time.Time) (event.Event, bool) {
	msg, ok := packet.ParseDNS(payload)
	if !ok || !msg.IsResponse {
		return event.Event{}, false
	}

	detail := map[string]any{"queryType": msg.QueryType}
	if len(msg.Answers) > 0 {
		detail["answers"] = msg.Answers
	}
	// 프로토콜은 지어내지 않고 패킷에서 본 것을 그대로 쓴다.
	return s.Factory.DNS(now, event.DNSInfo{Protocol: flow.Protocol, Domain: msg.Domain}, detail), true
}

// tlsEvent 는 ClientHello 가 완성되면 이벤트를 만든다.
// 같은 흐름에서 SNI 를 두 번 내지 않는 것은 Assembler 가 보장한다.
func (s *L7Sensor) tlsEvent(flow packet.Flow, payload []byte, assembler *packet.Assembler, now time.Time) (event.Event, bool) {
	if len(payload) == 0 {
		return event.Event{}, false // 순수 ACK 이나 SYN. 조립기에 넣을 것이 없다
	}
	hello, ok := assembler.Push(flow, payload, now)
	if !ok || hello.SNI == "" {
		// SNI 없는 핸드셰이크는 도메인을 말해 주지 않는다. 목적지 IP 는 network 이벤트에 이미 있다.
		return event.Event{}, false
	}

	// 주인은 이 자리에서 찾는다. 주기적으로 훑는 방식으로 바꾸면 짧게 산 연결은 영영 못 찾는다.
	var process string
	if s.Owner != nil {
		process = s.Owner.Lookup(flow.SrcPort, flow.DstIP, flow.DstPort)
	}
	// 주인을 못 찾아도 버리지 않는다. 버리면 어느 도메인에 접속했는지까지 같이 잃는다.

	detail := map[string]any{"l7Protocol": l7ProtocolTLS}
	if hello.Version != "" {
		detail["tlsVersion"] = hello.Version
	}
	if len(hello.ALPN) > 0 {
		detail["alpn"] = hello.ALPN
	}
	return s.Factory.L7(now, event.L7Info{
		ProcessPath: process,
		Protocol:    flow.Protocol,
		Domain:      hello.SNI,
		DestIP:      flow.DstIP,
		DestPort:    flow.DstPort,
	}, detail), true
}

// l7 이벤트가 어느 프로토콜에서 나왔는지 표시하는 값.
// 한 타입에 TLS 와 HTTP 가 같이 들어와서, 이게 없으면 조사할 때 둘을 구분할 수 없다.
const (
	l7ProtocolTLS  = "TLS"
	l7ProtocolHTTP = "HTTP"
)

// httpEvent 는 평문 HTTP 에서 이벤트를 만든다. TLS 와 달리 응답도 받고, 재조립은 하지 않는다.
func (s *L7Sensor) httpEvent(flow packet.Flow, payload []byte, now time.Time) (event.Event, bool) {
	msg, ok := packet.ParseHTTP(payload)
	if !ok {
		return event.Event{}, false // 80 번을 쓰는 다른 프로토콜이거나 헤더가 아닌 조각이다
	}
	// Host 없는 요청은 도메인을 말해 주지 않는다. 응답까지 이 조건에 넣으면 상태 코드를 다 잃는다.
	if !msg.IsResponse && msg.Host == "" {
		return event.Event{}, false
	}

	// 요청 쪽에서만 찾는다. 응답의 출발지 포트는 서버 것이라 엉뚱한 프로세스가 붙는다.
	var process string
	if s.Owner != nil && !msg.IsResponse {
		process = s.Owner.Lookup(flow.SrcPort, flow.DstIP, flow.DstPort)
	}

	detail := map[string]any{"l7Protocol": l7ProtocolHTTP}
	putDetail(detail, "httpMethod", msg.Method)
	putDetail(detail, "httpPath", msg.Path)
	putDetail(detail, "httpUserAgent", msg.UserAgent)
	if msg.StatusCode > 0 {
		detail["httpStatusCode"] = msg.StatusCode
	}

	return s.Factory.L7(now, event.L7Info{
		ProcessPath: process,
		Protocol:    flow.Protocol,
		// Host 헤더를 도메인 자리에 넣는다. TLS 의 SNI 와 같은 뜻이라 한 컬럼으로 조회된다.
		Domain:   msg.Host,
		DestIP:   flow.DstIP,
		DestPort: flow.DstPort,
	}, detail), true
}

// putDetail 은 빈 값이 아닌 것만 담는다. 빈 문자열이 쌓이면 조사 화면에서 걸러 낼 수 없다.
func putDetail(detail map[string]any, key, value string) {
	if value != "" {
		detail[key] = value
	}
}

func (s *L7Sensor) log() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}
