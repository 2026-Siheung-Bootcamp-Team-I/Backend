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
//
// 센서가 /dev/bpf 를 직접 열지 않고 이 인터페이스를 거치는 이유는 조립 로직을 테스트하기
// 위해서다. BPF 장치는 root 가 있어야 열리고 결과가 그때그때 네트워크 상태에 달려 있어서,
// 그 위에 로직을 얹으면 개발 기기에서 검증할 수 있는 것이 사실상 없어진다.
type PacketSource interface {
	// Packets 는 캡처한 프레임을 준다. 채널이 닫히면 캡처가 끝난 것이다.
	Packets() <-chan []byte
	Close() error
}

// SocketOwner 는 흐름의 주인 프로세스를 찾는다.
//
// 메서드 이름이 Owner 가 아니라 Lookup 인 이유는 L7Sensor 의 필드 이름이 Owner 이기 때문이다.
// 양쪽을 다 Owner 로 두면 호출부가 s.Owner.Owner(...) 가 되어 무엇이 무엇인지 읽히지 않는다.
type SocketOwner interface {
	// Lookup 은 로컬 포트로 프로세스 실행 경로를 찾는다. 못 찾으면 빈 문자열이다.
	Lookup(localPort int, remoteIP string, remotePort int) string
}

// L7Sensor 는 캡처한 패킷에서 DNS 응답과 TLS SNI 를 뽑아 이벤트로 만든다.
//
// 이 센서 하나가 dns 와 l7 두 종류를 다 낸다. 둘 다 같은 패킷 흐름에서 나오는 값이라
// 캡처를 두 번 열 이유가 없다. BPF 장치는 프로세스마다 하나씩 점유하는 자원이기도 하다.
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
//
// 입력은 네트워크에서 온 신뢰할 수 없는 바이트다. packet 패키지는 어떤 입력에도 panic 하지
// 않기로 되어 있지만, 그 계약이 깨지는 날 에이전트 전체가 죽는 것과 패킷 한 장을 잃는 것
// 사이의 차이가 커서 여기서 한 번 더 막는다. 관측을 계속하는 것이 이 프로그램의 존재 이유다.
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
		return s.dnsEvent(payload, now)
	case flow.Protocol == "tcp" && flow.DstPort == portHTTPS:
		return s.tlsEvent(flow, payload, assembler, now)
	}
	return event.Event{}, false
}

// dnsEvent 는 DNS 응답에서 이벤트를 만든다.
//
// **응답만 낸다.** 질의와 응답은 같은 도메인을 담고 있어서 둘 다 내면 대시보드에 같은 줄이
// 두 번 올라간다. 그중 응답을 고른 이유는 도메인이 어느 IP 로 풀렸는지까지 담기 때문이다.
// 그 IP 가 있어야 나중에 network 이벤트의 목적지와 이어 붙여 "이 프로세스가 이 도메인에
// 접속했다" 를 복원할 수 있다.
//
// 놓치는 것: 응답이 아예 오지 않은 질의다. DNS 서버가 닿지 않거나 타임아웃된 경우가 그렇다.
// 없는 도메인을 물었을 때는 서버가 NXDOMAIN 응답을 주므로 이쪽은 answers 만 빈 채로 잡힌다.
//
// **프로세스는 붙이지 않는다.** macOS 의 DNS 질의는 앱이 직접 53번 포트로 쏘는 것이 아니라
// 전부 mDNSResponder 를 거쳐 나간다. 그래서 이 UDP 소켓의 주인을 찾으면 언제나
// mDNSResponder 가 나오고, 그건 실제로 질의한 앱이 아니다. 틀린 프로세스를 채우면 조사하는
// 사람이 그 값을 믿고 엉뚱한 결론을 내므로, 비워 두는 편이 낫다. 진짜 질의자는 같은 시각의
// l7 이벤트나 network 이벤트에서 찾아야 한다.
func (s *L7Sensor) dnsEvent(payload []byte, now time.Time) (event.Event, bool) {
	msg, ok := packet.ParseDNS(payload)
	if !ok || !msg.IsResponse {
		return event.Event{}, false
	}

	detail := map[string]any{"queryType": msg.QueryType}
	if len(msg.Answers) > 0 {
		detail["answers"] = msg.Answers
	}
	return s.Factory.DNS(now, "", msg.Domain, detail), true
}

// tlsEvent 는 ClientHello 가 완성되면 이벤트를 만든다.
//
// 같은 흐름에서 SNI 를 두 번 내지 않는 것은 Assembler 가 보장한다. 완성한 흐름을 바로
// 버리므로 재전송된 ClientHello 는 다시 완성되지 않는다.
func (s *L7Sensor) tlsEvent(flow packet.Flow, payload []byte, assembler *packet.Assembler, now time.Time) (event.Event, bool) {
	if len(payload) == 0 {
		return event.Event{}, false // 순수 ACK 이나 SYN. 조립기에 넣을 것이 없다
	}
	hello, ok := assembler.Push(flow, payload, now)
	if !ok || hello.SNI == "" {
		// SNI 없는 핸드셰이크는 도메인을 말해 주지 않는다. 목적지 IP 는 network 이벤트에 이미 있다.
		return event.Event{}, false
	}

	// 소켓 주인은 지금 이 자리에서 찾는다. ClientHello 를 방금 봤다는 것은 그 소켓이 이 순간
	// 확실히 열려 있다는 뜻이라 거의 반드시 찾힌다. 주기적으로 훑는 방식이었다면 짧게 살다 간
	// 연결은 다음 주기 전에 닫혀 영영 못 찾는다.
	var process string
	if s.Owner != nil {
		process = s.Owner.Lookup(flow.SrcPort, flow.DstIP, flow.DstPort)
	}
	// 주인을 못 찾아도 이벤트는 낸다. 어느 도메인에 접속했는지는 프로세스를 몰라도 쓸모가 있다.

	detail := map[string]any{}
	if hello.Version != "" {
		detail["tlsVersion"] = hello.Version
	}
	if len(hello.ALPN) > 0 {
		detail["alpn"] = hello.ALPN
	}
	return s.Factory.L7(now, process, hello.SNI, flow.DstIP, flow.DstPort, detail), true
}

func (s *L7Sensor) log() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}
