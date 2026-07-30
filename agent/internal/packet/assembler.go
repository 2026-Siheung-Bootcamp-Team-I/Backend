package packet

import (
	"encoding/binary"
	"time"
)

// Assembler 는 흐름별로 TCP 페이로드 앞부분을 모아 ClientHello 를 완성시킨다.
//
// 이게 필요한 이유는 ClientHello 가 한 패킷에 안 들어오기 때문이다. 예외적인 상황이 아니라
// 요즘의 기본값이다. Chrome, Firefox, Go 의 crypto/tls 가 양자내성 키교환을 기본으로 보내면서
// ClientHello 가 1500 바이트를 넘었고 두 세그먼트로 쪼개진다. 첫 세그먼트만 보고 판단하면
// 요즘 브라우저의 SNI 를 거의 다 놓친다.
//
// 완전한 TCP 재조립은 하지 않는다. 순서 뒤바뀜과 중복을 다 다루려면 상태가 훨씬 커지는데,
// 우리가 필요한 건 연결 맨 앞의 몇 KB 뿐이다. 도착 순서대로 이어 붙이고 안 맞으면 포기한다.
//
// 신뢰할 수 없는 입력을 버퍼에 쌓는 코드라 상한이 필수다. 바이트 수, 세그먼트 수, 시간,
// 동시 흐름 수를 전부 막아 둔다. 하나라도 빠지면 메모리 고갈 공격의 표적이 된다.
//
// 동시성 보호는 하지 않는다. 캡처 루프 하나가 순서대로 부르는 것을 전제로 한다.
type Assembler struct {
	flows map[Flow]*assemblyBuffer
	// done 은 이미 SNI 를 뽑아낸 흐름이다.
	//
	// TCP 는 응답이 없으면 같은 세그먼트를 다시 보낸다. 완성한 흐름을 그냥 잊으면 재전송된
	// ClientHello 를 새 핸드셰이크로 보고 같은 도메인을 또 올린다. 대시보드에서 한 번의 접속이
	// 여러 번으로 보이면 조사하는 사람이 규모를 잘못 읽는다.
	done map[Flow]time.Time
}

const (
	// assemblerMaxBytes 는 한 흐름에서 모을 최대 바이트다.
	// ClientHello 는 아무리 커도 몇 KB 라 이 정도면 넉넉하다.
	assemblerMaxBytes = 8 * 1024
	// assemblerMaxSegments 는 한 흐름에서 받을 최대 세그먼트 수다.
	// 잘게 쪼개 보내며 버퍼만 채우는 것을 막는다.
	assemblerMaxSegments = 5
	// assemblerTTL 은 완성되지 않은 흐름을 들고 있는 시간이다.
	// 핸드셰이크는 시작하면 곧바로 끝나므로 길게 잡을 이유가 없다.
	assemblerTTL = 10 * time.Second
	// assemblerMaxFlows 는 동시에 추적할 흐름 수다.
	assemblerMaxFlows = 4096
)

type assemblyBuffer struct {
	data     []byte
	segments int
	seen     time.Time
}

// NewAssembler 는 조립기를 만든다.
func NewAssembler() *Assembler {
	return &Assembler{
		flows: make(map[Flow]*assemblyBuffer),
		done:  make(map[Flow]time.Time),
	}
}

// Len 은 지금 모으고 있는 흐름 수다. 완성한 흐름은 세지 않는다.
// 상한이 실제로 걸리는지 확인하는 데 쓴다.
func (a *Assembler) Len() int { return len(a.flows) }

// Push 는 세그먼트를 넣고, ClientHello 가 완성됐으면 파싱해 돌려준다.
//
// 완성했거나 이 흐름이 가망 없다고 판단하면 흐름을 버린다. 그래서 같은 흐름에서 두 번
// 완성되지 않는다. 재전송된 패킷이 같은 SNI 를 다시 만들어 내면 중복 이벤트가 된다.
func (a *Assembler) Push(flow Flow, payload []byte, now time.Time) (ClientHello, bool) {
	a.expire(now)

	if len(payload) == 0 {
		return ClientHello{}, false
	}
	if _, already := a.done[flow]; already {
		return ClientHello{}, false // 재전송이다. 같은 도메인을 두 번 올리지 않는다
	}

	buf := a.flows[flow]
	if buf == nil {
		// 첫 세그먼트가 TLS 핸드셰이크가 아니면 이 흐름은 볼 이유가 없다.
		// 여기서 걸러야 443 이 아닌 트래픽이 섞여 들어와도 버퍼를 먹지 않는다.
		if payload[0] != recordHandshake {
			return ClientHello{}, false
		}
		if len(a.flows) >= assemblerMaxFlows {
			a.dropOldest()
		}
		buf = &assemblyBuffer{}
		a.flows[flow] = buf
	}

	buf.data = append(buf.data, payload...)
	buf.segments++
	buf.seen = now

	if hello, ok := ParseClientHello(buf.data); ok {
		delete(a.flows, flow)
		a.done[flow] = now
		return hello, true
	}

	// 아직 못 읽었다. 더 기다릴 가치가 있는지 본다.
	if !a.worthWaiting(buf) {
		delete(a.flows, flow)
	}
	return ClientHello{}, false
}

// worthWaiting 은 이 흐름을 계속 들고 있을지 정한다.
func (a *Assembler) worthWaiting(buf *assemblyBuffer) bool {
	if len(buf.data) >= assemblerMaxBytes || buf.segments >= assemblerMaxSegments {
		return false
	}
	// 레코드 헤더를 읽을 수 있으면 필요한 전체 길이를 알 수 있다. 그보다 이미 많이 받았는데도
	// 파싱이 안 됐다면 더 기다려 봐야 소용없다.
	if need, ok := recordTotalLen(buf.data); ok && len(buf.data) >= need {
		return false
	}
	return true
}

// recordTotalLen 은 첫 TLS 레코드를 다 담는 데 필요한 바이트 수를 준다.
func recordTotalLen(b []byte) (int, bool) {
	if len(b) < 5 {
		return 0, false
	}
	return 5 + int(binary.BigEndian.Uint16(b[3:5])), true
}

// expire 는 오래된 흐름을 지운다.
//
// 핸드셰이크가 끊기거나 서버가 응답하지 않으면 흐름이 완성되지 않은 채 남는다. 정리하지 않으면
// 오래 도는 에이전트에서 맵이 계속 커진다.
func (a *Assembler) expire(now time.Time) {
	for flow, buf := range a.flows {
		if now.Sub(buf.seen) >= assemblerTTL {
			delete(a.flows, flow)
		}
	}
	// 완성 기록도 같은 주기로 지운다. 포트는 재사용되므로 영원히 들고 있으면 나중에 같은
	// 4-튜플로 생긴 진짜 새 연결의 SNI 를 재전송으로 오해해 버린다.
	for flow, at := range a.done {
		if now.Sub(at) >= assemblerTTL {
			delete(a.done, flow)
		}
	}
	if len(a.done) > assemblerMaxFlows {
		a.done = make(map[Flow]time.Time)
	}
}

// dropOldest 는 가장 오래 갱신되지 않은 흐름을 버린다.
//
// 상한에 걸렸다는 건 대개 짧은 연결이 몰려 들어온 상황이라, 정교한 축출 정책을 둘 이유가 없다.
// 맵이 무한정 커지는 것만 막으면 된다.
func (a *Assembler) dropOldest() {
	var oldest Flow
	var oldestAt time.Time
	first := true
	for flow, buf := range a.flows {
		if first || buf.seen.Before(oldestAt) {
			oldest, oldestAt, first = flow, buf.seen, false
		}
	}
	if !first {
		delete(a.flows, oldest)
	}
}
