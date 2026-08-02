package packet

import (
	"encoding/binary"
	"time"
)

// Assembler 는 흐름별로 TCP 페이로드 앞부분을 모아 ClientHello 를 완성시킨다.
// 동시성 보호는 하지 않는다. 캡처 루프 하나가 순서대로 부르는 것을 전제로 한다.
type Assembler struct {
	flows map[Flow]*assemblyBuffer
	// done 을 없애면 재전송된 ClientHello 를 새 핸드셰이크로 보고 같은 도메인을 또 올린다.
	done map[Flow]time.Time
}

// 상한 넷 중 하나라도 빼면 신뢰할 수 없는 입력으로 메모리를 고갈시킬 수 있다.
const (
	// assemblerMaxBytes 는 한 흐름에서 모을 최대 바이트다.
	assemblerMaxBytes = 8 * 1024
	// assemblerMaxSegments 는 한 흐름에서 받을 최대 세그먼트 수다.
	assemblerMaxSegments = 5
	// assemblerTTL 은 완성되지 않은 흐름을 들고 있는 시간이다.
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
func (a *Assembler) Len() int { return len(a.flows) }

// Push 는 세그먼트를 넣고, ClientHello 가 완성됐으면 파싱해 돌려준다.
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
		// 여기서 안 걸러내면 443 이 아닌 트래픽이 섞여 들어와 버퍼를 먹는다.
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
	// 위 상한과 별개다. 필요한 전체 길이를 다 받고도 파싱이 안 됐으면 더 기다려야 소용없다.
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

// expire 는 오래된 흐름을 지운다. 정리하지 않으면 오래 도는 에이전트에서 맵이 계속 커진다.
func (a *Assembler) expire(now time.Time) {
	for flow, buf := range a.flows {
		if now.Sub(buf.seen) >= assemblerTTL {
			delete(a.flows, flow)
		}
	}
	// 포트는 재사용된다. 완성 기록을 영원히 들고 있으면 같은 4-튜플의 새 연결을 재전송으로 오해한다.
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
