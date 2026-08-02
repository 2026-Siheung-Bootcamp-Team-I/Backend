package sensor

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"sync/atomic"

	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/packet"
)

// Microsoft-Windows-PktMon 프로바이더의 이벤트 160(패킷)에서 프레임 바이트를 꺼낸다.
// 순수한 계산이라 빌드 태그 없이 두고 개발 기기에서 검증한다.

const (
	// eventPktMonPacket 은 프레임 바이트를 싣고 오는 이벤트 ID 다.
	eventPktMonPacket = 160

	// pktMonKeywordPayload 는 프레임 바이트를 받으려면 켜야 하는 keyword 다.
	// 안 켜면 세션도 프로바이더도 멀쩡한데 이벤트 160 만 한 건도 오지 않는다.
	pktMonKeywordPayload = 0x10
)

// PKTMON_PACKET_TYPE. 페이로드가 어느 계층부터 시작하는지를 말해 준다.
// 3 을 IP 로 읽는 것은 드라이버 헤더 기준이다. NetMon 파서(.npl)의 옛 표를 따르면 조용히 0건이 된다.
const (
	pktMonPayloadUnknown  = 0
	pktMonPayloadEthernet = 1
	pktMonPayloadWiFi     = 2
	pktMonPayloadIP       = 3
)

// PKTMON_DIRECTION_TAG. 어느 방향으로 흐르던 패킷을 보고한 것인지다.
const (
	pktMonDirUnspecified = 0
	pktMonDirIn          = 1
	pktMonDirOut         = 2
	pktMonDirRx          = 3
	pktMonDirTx          = 4
	pktMonDirIngress     = 5
	pktMonDirEgress      = 6
)

// 이벤트 160 의 payload 안에서 우리가 읽을 필드 위치.
// 구조체로 캐스팅하면 안 된다. DropReason 이 22 라 정렬이 안 맞고, 컴파일러 패딩이 뒤 필드를 전부 민다.
const (
	pktMonOffDirTag     = 12
	pktMonOffPacketType = 14
	pktMonOffLoggedSize = 32
	// pktMonHeaderLen 은 프레임 바이트가 시작하는 위치다. LoggedPayloadSize 바로 뒤다.
	pktMonHeaderLen = pktMonOffLoggedSize + 2
)

// pktMonFrame 은 이벤트 160 하나에서 꺼낸 값이다.
type pktMonFrame struct {
	DirTag     uint16
	PacketType uint16
	// Payload 는 입력 버퍼를 가리키는 슬라이스다. 넘기기 전에 반드시 복사해야 한다.
	Payload []byte
}

// pktMonReject 는 프레임을 버린 이유다.
// 버리는 자리마다 이유를 남기지 않으면 "이벤트 0건" 의 원인을 좁힐 방법이 없다.
type pktMonReject int

const (
	pktMonAccept pktMonReject = iota
	// pktMonRejectShort 은 헤더조차 다 안 들어온 경우다.
	pktMonRejectShort
	// pktMonRejectSizeMismatch 는 LoggedPayloadSize 와 실제 바이트 수가 안 맞는 경우다.
	// 이게 쌓이면 우리가 읽는 필드 위치가 이 Windows 판과 어긋난 것이다. 가장 중요한 신호다.
	pktMonRejectSizeMismatch
	// pktMonRejectEmpty 는 프레임 바이트가 0 인 경우다. keyword 0x10 을 안 켜면 이렇게 온다.
	pktMonRejectEmpty
	// pktMonRejectInbound 는 들어오는 쪽 패킷이라 버린 경우다.
	pktMonRejectInbound
	// pktMonRejectLinkType 은 이더넷도 raw IP 도 아닌 페이로드다. WiFi 프레임이 여기 온다.
	pktMonRejectLinkType
	// pktMonRejectQueueFull 은 센서가 밀려 큐가 찬 경우다.
	pktMonRejectQueueFull

	pktMonRejectCount
)

// String 은 로그에 남길 이름이다.
func (r pktMonReject) String() string {
	switch r {
	case pktMonAccept:
		return "accept"
	case pktMonRejectShort:
		return "short"
	case pktMonRejectSizeMismatch:
		return "sizeMismatch"
	case pktMonRejectEmpty:
		return "empty"
	case pktMonRejectInbound:
		return "inbound"
	case pktMonRejectLinkType:
		return "linkType"
	case pktMonRejectQueueFull:
		return "queueFull"
	}
	return "unknown(" + strconv.Itoa(int(r)) + ")"
}

// parsePktMonPacket 은 이벤트 160 의 payload 에서 프레임을 꺼낸다.
// 길이 검사가 둘이다. 두 번째(LoggedPayloadSize)를 빼면 오프셋이 어긋나도 이유 없는 0건이 된다.
func parsePktMonPacket(userData []byte) (pktMonFrame, pktMonReject) {
	if len(userData) < pktMonHeaderLen {
		return pktMonFrame{}, pktMonRejectShort
	}

	logged := int(binary.LittleEndian.Uint16(userData[pktMonOffLoggedSize:]))
	if logged == 0 {
		return pktMonFrame{}, pktMonRejectEmpty
	}
	// ETW 는 payload 를 딱 맞게 채워 보낸다. 모자라든 남든 배치가 어긋났다는 신호다.
	if pktMonHeaderLen+logged != len(userData) {
		return pktMonFrame{}, pktMonRejectSizeMismatch
	}

	return pktMonFrame{
		DirTag:     binary.LittleEndian.Uint16(userData[pktMonOffDirTag:]),
		PacketType: binary.LittleEndian.Uint16(userData[pktMonOffPacketType:]),
		Payload:    userData[pktMonHeaderLen:],
	}, pktMonAccept
}

// pktMonInbound 는 들어오는 쪽 패킷인지 본다.
// 모르는 태그는 반드시 false 다. true 로 뒤집으면 모르는 태그를 쓰는 판에서 모든 프레임이 사라진다.
func pktMonInbound(dirTag uint16) bool {
	switch dirTag {
	case pktMonDirIn, pktMonDirRx, pktMonDirIngress:
		return true
	}
	return false
}

// pktMonEthernetFrame 은 프레임을 이더넷 프레임 하나로 맞춰 복사해 준다.
// raw IP 프레임 앞에는 14바이트 이더넷 헤더를 지어 붙인다. MAC 자리는 0 이고 아무도 안 읽는다.
func pktMonEthernetFrame(f pktMonFrame) ([]byte, pktMonReject) {
	switch f.PacketType {
	case pktMonPayloadEthernet:
		// ETW 버퍼는 곧 덮어써진다. 반드시 복사해서 넘긴다.
		frame := make([]byte, len(f.Payload))
		copy(frame, f.Payload)
		return frame, pktMonAccept

	case pktMonPayloadIP:
		etherType, ok := pktMonEtherTypeOf(f.Payload)
		if !ok {
			return nil, pktMonRejectLinkType
		}
		frame := make([]byte, etherHeaderLen+len(f.Payload))
		binary.BigEndian.PutUint16(frame[etherTypeOffset:], etherType)
		copy(frame[etherHeaderLen:], f.Payload)
		return frame, pktMonAccept
	}
	// WiFi(2) 는 802.11 프레임이라 packet.Parse 가 다루지 못한다. Unknown(0)도 마찬가지다.
	return nil, pktMonRejectLinkType
}

// pktMonKeepInbound 는 들어오는 프레임을 살릴지 본다.
// 방향만 보고 자르면 HTTP 응답의 상태 코드를 잃고, 안 자르면 들어오는 443 이 CPU 만 쓴다.
func pktMonKeepInbound(frame []byte) bool {
	flow, _, ok := packet.Parse(frame, packet.LinkEthernet)
	if !ok {
		return false
	}
	return flow.Protocol == "tcp" && (flow.SrcPort == portHTTP || flow.DstPort == portHTTP)
}

// pktMonEtherTypeOf 는 IP 헤더 첫 바이트의 버전으로 EtherType 을 정한다.
func pktMonEtherTypeOf(ip []byte) (uint16, bool) {
	if len(ip) == 0 {
		return 0, false
	}
	switch ip[0] >> 4 {
	case 4:
		return etherTypeIPv4, true
	case 6:
		return etherTypeIPv6, true
	}
	return 0, false
}

// pktMonStats 는 이유별로 프레임 수를 센다.
type pktMonStats struct {
	counts [pktMonRejectCount]atomic.Uint64
	// types 는 실제로 본 PacketType 값을 센다. 없으면 실기기 프레임이 이더넷인지 IP 인지 못 가린다.
	types [4]atomic.Uint64
	// dirs 는 실제로 본 DirTag 값을 센다. 판마다 다를 수 있어 방향 판정을 조이려면 실측이 있어야 한다.
	dirs [8]atomic.Uint64
}

func (s *pktMonStats) count(r pktMonReject) {
	if r >= 0 && r < pktMonRejectCount {
		s.counts[r].Add(1)
	}
}

func (s *pktMonStats) observe(f pktMonFrame) {
	if int(f.PacketType) < len(s.types) {
		s.types[f.PacketType].Add(1)
	}
	if int(f.DirTag) < len(s.dirs) {
		s.dirs[f.DirTag].Add(1)
	}
}

// logArgs 는 slog 에 넘길 키/값을 만든다.
// 0 인 항목은 빼되 accept 는 0 이어도 남긴다. 0건이라는 사실 자체가 우리가 찾는 신호다.
func (s *pktMonStats) logArgs() []any {
	args := []any{"accept", s.counts[pktMonAccept].Load()}
	for r := pktMonAccept + 1; r < pktMonRejectCount; r++ {
		if n := s.counts[r].Load(); n > 0 {
			args = append(args, r.String(), n)
		}
	}
	for t := range s.types {
		if n := s.types[t].Load(); n > 0 {
			args = append(args, "packetType"+strconv.Itoa(t), n)
		}
	}
	for d := range s.dirs {
		if n := s.dirs[d].Load(); n > 0 {
			args = append(args, "dirTag"+strconv.Itoa(d), n)
		}
	}
	return args
}

// pktmon.exe 에 넘길 인자. 문자열을 만드는 일이라 여기 두면 개발 기기에서 검증된다.

// pktMonFilterName 은 우리가 다는 필터 이름이다.
const pktMonFilterName = "EDRdog-TLS"

// pktMonFilterArgs 는 커널 필터를 다는 명령의 인자다.
// 필터 하나가 포트 하나만 받아 포트마다 따로 걸어야 한다. 안 걸면 모든 패킷이 ETW 로 올라온다.
func pktMonFilterArgs(port int) []string {
	return []string{"filter", "add", pktMonFilterName, "-t", "TCP", "-p", strconv.Itoa(port)}
}

// pktMonStartArgs 는 캡처를 시작하는 명령의 인자다.
// --comp nics 를 빼면 한 패킷이 여러 컴포넌트에서 보고돼 양이 몇 배가 되고,
// --pkt-size 를 기본값 128 로 두면 ClientHello 가 잘려 SNI 를 못 뽑는다.
func pktMonStartArgs(pktSize int, etlPath string) []string {
	return []string{
		"start", "--capture",
		"--comp", "nics",
		"--pkt-size", strconv.Itoa(pktSize),
		"--flags", "0x10",
		"--log-mode", "memory",
		"--file-size", "1",
		"--file-name", etlPath,
	}
}

// pktMonProviderSpec 은 golang-etw 의 ParseProvider 에 넘길 프로바이더 설정이다.
// 형식은 이름:EnableLevel:이벤트ID들:MatchAnyKeyword 다.
// 이벤트 ID 를 빼면 설정/랜다운 이벤트까지 콜백으로 올라온다.
func pktMonProviderSpec() string {
	return fmt.Sprintf("Microsoft-Windows-PktMon:0xff:%d:%#x", eventPktMonPacket, pktMonKeywordPayload)
}
