package sensor

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"sync/atomic"
)

// 이 파일에는 빌드 태그가 없다.
//
// pktmon 이벤트를 실제로 받는 것은 Windows 에서만 되지만, 그 이벤트에서 프레임 바이트를
// 꺼내는 일은 바이트 배열 하나를 읽는 순수한 계산이다. 그 부분을 여기로 빼서 개발 기기에서
// 검증한다. etw_map.go 와 같은 이유이고 같은 방식이다.
//
// 이 파일이 다루는 것은 Microsoft-Windows-PktMon 프로바이더의 이벤트 160(패킷) 하나다.

const (
	// eventPktMonPacket 은 프레임 바이트를 싣고 오는 이벤트 ID 다.
	//
	// Microsoft 의 etl2pcapng 이 `#define tidPktmonPacket 160` 으로 같은 값을 쓴다.
	// 170 은 버려진 패킷(PacketDrop)인데 우리는 받지 않는다. 나간 적 없는 패킷의 SNI 는
	// "이 호스트가 어디에 접속했다" 를 뜻하지 않는다.
	eventPktMonPacket = 160

	// pktMonKeywordPayload 는 프레임 바이트를 받으려면 켜야 하는 keyword 다.
	//
	// 값의 근거는 Microsoft 가 낸 NetMon 파서(etl_Microsoft-Windows-PktMon-Events.npl)의
	// keyword 비트 정의다. 순서가 Config(bit0), Rundown(bit1), NblParsed(bit2), NblInfo(bit3),
	// Payload(bit4) 라 Payload 는 1<<4 = 0x10 이다.
	// 이걸 안 켜면 세션도 프로바이더도 멀쩡한데 이벤트 160 만 한 건도 오지 않는다.
	pktMonKeywordPayload = 0x10
)

// PKTMON_PACKET_TYPE. 페이로드가 어느 계층부터 시작하는지를 말해 준다.
//
// 값은 Windows 드라이버 헤더 pktmonnpik.h 의 enum 그대로다. Microsoft 의 etl2pcapng 도
// 같은 표를 쓰고 1 을 이더넷, 3 을 raw IP 로 옮긴다.
//
// **주의.** 같은 Microsoft 가 낸 NetMon 파서(.npl)는 3 을 "MBB" 라고 적어 두었는데 그쪽이
// 오래된 표다. 드라이버 헤더와 etl2pcapng 두 곳이 IP 로 일치하므로 그것을 따른다.
// 이 값을 잘못 읽으면 IP 헤더를 이더넷 헤더로 읽어 조용히 0건이 된다.
const (
	pktMonPayloadUnknown  = 0
	pktMonPayloadEthernet = 1
	pktMonPayloadWiFi     = 2
	pktMonPayloadIP       = 3
)

// PKTMON_DIRECTION_TAG. 어느 방향으로 흐르던 패킷을 보고한 것인지다.
//
// 값은 pktmonnpik.h 의 enum 이다. In/Rx/Ingress 가 받는 쪽이고 Out/Tx/Egress 가 보내는 쪽이며,
// Unspecified 는 어느 쪽인지 말하지 않는 것이다.
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
//
// 구조체를 만들어 통째로 캐스팅하지 않는다. 아래 배치를 보면 DropReason(UINT32)이 22 에
// 놓여 있는데 이건 4바이트 정렬이 아니다. Go 구조체로 옮기면 컴파일러가 패딩을 넣어 그
// 뒤 필드가 전부 밀리고, 그런 어긋남은 오류를 내지 않고 조용히 틀린 값을 준다.
// 이 저장소는 macOS 캡처에서 정확히 같은 사고를 이미 한 번 겪었다(pcap_darwin.go 의
// bpfHdrLenOffset 주석).
//
// 근거는 두 곳이다.
//
//  1. Microsoft 의 NetMon 파서 etl_Microsoft-Windows-PktMon-Events.npl 의 PktMon_FramePayload:
//     UINT64 PktGroupId; UINT16 PktNumber; UINT16 AppearanceCount; UINT16 DirTag;
//     UINT16 PacketType; UINT16 ComponentId; UINT16 EdgeId; UINT16 FilterId;
//     UINT32 DropReason; UINT32 DropLocation; UINT16 OriginalPayloadSize;
//     UINT16 LoggedPayloadSize; 그 뒤가 프레임 바이트다.
//  2. 드라이버 헤더의 PKTMON_EVT_STREAM_METADATA. 앞 30바이트의 필드 이름과 순서가
//     위와 정확히 같다(PktGroupId, PktCount, AppearanceCount, DirectionName, PacketType,
//     ComponentId, EdgeId, FilterId, DropReason, DropLocation).
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
	// Payload 는 입력 버퍼를 가리키는 슬라이스다. ETW 콜백이 준 버퍼는 곧 덮어써지므로
	// 채널로 넘기기 전에 반드시 복사해야 한다. pktMonEthernetFrame 이 그 복사를 한다.
	Payload []byte
}

// pktMonReject 는 프레임을 버린 이유다.
//
// 이유마다 번호를 두는 것은 셀 수 있게 하려는 것이다. 이 프로젝트에서 가장 찾기 어려운
// 고장이 "세션도 필터도 멀쩡한데 이벤트가 0건" 이라, 버리는 자리마다 왜 버렸는지 남기지
// 않으면 원인을 좁힐 수가 없다.
type pktMonReject int

const (
	pktMonAccept pktMonReject = iota
	// pktMonRejectShort 은 헤더조차 다 안 들어온 경우다.
	pktMonRejectShort
	// pktMonRejectSizeMismatch 는 LoggedPayloadSize 와 실제 바이트 수가 안 맞는 경우다.
	// 우리가 읽는 필드 위치가 이 Windows 판과 어긋났다는 뜻이라 가장 중요한 신호다.
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
//
// 길이 검사를 두 번 한다. 먼저 헤더가 다 왔는지 보고, 그다음 LoggedPayloadSize 가 실제
// 남은 바이트와 맞는지 본다. 두 번째가 핵심이다. 우리가 잡은 오프셋이 이 Windows 판의
// 실제 배치와 다르면 32번 자리에서 읽은 값이 프레임 길이일 리가 없어서 거의 반드시 어긋난다.
// 그 어긋남을 여기서 잡아 이유가 있는 0건으로 만든다. 이유 없는 0건이 제일 나쁘다.
func parsePktMonPacket(userData []byte) (pktMonFrame, pktMonReject) {
	if len(userData) < pktMonHeaderLen {
		return pktMonFrame{}, pktMonRejectShort
	}

	logged := int(binary.LittleEndian.Uint16(userData[pktMonOffLoggedSize:]))
	if logged == 0 {
		return pktMonFrame{}, pktMonRejectEmpty
	}
	// 남은 바이트가 모자라면 우리가 읽는 배치가 틀린 것이다. 넘치는 것은 허용하지 않는다.
	// ETW 는 이벤트 payload 를 딱 맞게 채워 보내므로 뒤에 남는 바이트가 있을 이유가 없고,
	// 있다면 그 역시 배치가 어긋났다는 신호다.
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
//
// 모르는 값은 false 다. 즉 못 알아본 방향은 통과시킨다. 반대로 만들면(모르는 값을 들어오는
// 쪽으로 보면) Windows 판이 우리가 모르는 태그를 쓰는 순간 모든 프레임이 조용히 사라진다.
// 나가는 것만 필요하다는 것은 부하를 줄이려는 최적화이지 정확성 조건이 아니다. L7Sensor 가
// 목적지 포트 443 만 보므로 들어오는 프레임이 섞여 들어와도 이벤트가 잘못 나지는 않는다.
func pktMonInbound(dirTag uint16) bool {
	switch dirTag {
	case pktMonDirIn, pktMonDirRx, pktMonDirIngress:
		return true
	}
	return false
}

// pktMonEthernetFrame 은 프레임을 이더넷 프레임 하나로 맞춰 복사해 준다.
//
// L7Sensor 의 LinkType 은 센서를 만들 때 한 번 정하는 값인데, pktmon 은 프레임마다
// PacketType 으로 이더넷인지 IP 헤더부터인지를 알려 준다. 둘을 맞추는 방법은 둘 중 하나다.
// L7Sensor 를 프레임마다 링크 종류를 받도록 고치거나, 캡처 쪽에서 한 모양으로 맞춰 주거나.
// 후자를 골랐다. 검증된 센서를 건드리지 않아도 되고, "링크 종류를 잘못 짚어 조용히 0건" 이라는
// 실패 모드 자체가 없어진다.
//
// raw IP 프레임 앞에는 14바이트 이더넷 헤더를 지어 붙인다. MAC 주소 자리는 0 이다.
// packet.Parse 는 이더넷 헤더에서 EtherType 두 바이트만 읽고 MAC 은 보지 않으므로,
// 지어낸 값이 어떤 판단에도 쓰이지 않는다. EtherType 은 IP 버전에서 정한다.
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
	// types 는 실제로 본 PacketType 값을 센다. 실기기에서 프레임이 이더넷인지 IP 헤더부터인지
	// 확인해야 하는데, 코드가 이미 알고 있는 값을 로그에 그대로 내놓으면 사람이 볼 필요가 없다.
	types [4]atomic.Uint64
	// dirs 는 실제로 본 DirTag 값을 센다. 방향 태그를 어떤 값으로 보내는지가 판마다 다를 수
	// 있어서, 무엇이 왔는지를 남겨 두어야 방향 판정을 나중에 조일 수 있다.
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

// logArgs 는 slog 에 넘길 키/값을 만든다. 0 인 항목은 빼서 로그를 읽을 수 있게 남긴다.
// 다만 accept 는 0 이어도 남긴다. 0건이라는 사실 자체가 우리가 찾는 신호다.
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

// pktmon.exe 에 넘길 인자.
//
// 명령을 여기서 만드는 이유는 배선 파일이 Windows 전용이라 그쪽에 두면 인자 하나 바뀌는
// 것도 개발 기기에서 확인할 수 없기 때문이다. 문자열을 만드는 일이라 순수하게 검증된다.

// pktMonFilterName 은 우리가 다는 필터 이름이다. 사람이 `pktmon filter list` 로 봤을 때
// 이게 누구 것인지 알아볼 수 있어야 한다.
const pktMonFilterName = "EDRdog-TLS"

// pktMonFilterArgs 는 커널 필터를 다는 명령의 인자다.
//
// 필터를 안 걸면 그 기기를 지나는 모든 패킷이 ETW 로 올라온다. macOS 쪽에서 BPF 필터가
// 하는 일과 목적이 같다. TCP 이면서 포트가 443 인 것만 통과시킨다.
//
// -p 는 출발지와 목적지를 가리지 않는다(문서에 명시돼 있다). 그래서 서버가 보내온 443
// 패킷도 함께 올라오는데, 그건 pktMonInbound 로 걸러 낸다.
func pktMonFilterArgs(port int) []string {
	return []string{"filter", "add", pktMonFilterName, "-t", "TCP", "-p", strconv.Itoa(port)}
}

// pktMonStartArgs 는 캡처를 시작하는 명령의 인자다.
//
//   - --comp nics: 컴포넌트마다 같은 패킷이 한 번씩 올라오는 것을 막는다. 기본값 all 이면
//     한 패킷이 NIC, vSwitch 등에서 여러 번 보고돼 양이 몇 배가 된다.
//   - --pkt-size: 프레임에서 몇 바이트를 실을지다. 기본값 128 로는 ClientHello 의 SNI 확장이
//     통째로 잘려 도메인을 못 뽑는다. macOS 캡처와 같은 값을 쓴다.
//   - --flags 0x10: 프레임 바이트(raw packet)만 남긴다. 기본값 0x012 는 컴포넌트 정보(0x002)를
//     로그 파일 끝에 덧붙이는데 우리는 그 파일을 읽지 않는다.
//   - --log-mode memory: pktmon 자신의 로그를 메모리에 두고 stop 할 때 한 번만 파일로 쓴다.
//     우리는 우리 ETW 세션에서 이벤트를 직접 받으므로 이 파일이 필요 없다. 그런데 pktmon 은
//     로그 대상 없이 시작할 수 없어서, 가장 작고 디스크를 덜 쓰는 모양을 고른 것이다.
//   - --file-size 1: 그 버퍼를 1MB 로 묶는다.
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
//
// 형식은 이름:EnableLevel:이벤트ID들:MatchAnyKeyword 다. 이벤트 ID 를 적으면 커널이
// 걸러 주므로 설정/랜다운 이벤트가 우리 콜백까지 오지 않는다.
func pktMonProviderSpec() string {
	return fmt.Sprintf("Microsoft-Windows-PktMon:0xff:%d:%#x", eventPktMonPacket, pktMonKeywordPayload)
}
