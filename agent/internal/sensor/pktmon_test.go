package sensor

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/packet"
)

// pktMonEvent 는 이벤트 160 의 payload 를 짓는다.
//
// **pktmon.go 의 오프셋 상수를 일부러 쓰지 않는다.** 상수를 써서 픽스처를 만들면 상수가
// 틀려도 픽스처가 같이 틀려서 테스트가 통과한다. 이 저장소는 macOS 캡처에서 정확히 그
// 방식으로 실기기 0건 버그를 만든 적이 있다(pcap_darwin.go 의 bpfHdrLenOffset 주석).
//
// 그래서 여기서는 Microsoft 가 낸 NetMon 파서(etl_Microsoft-Windows-PktMon-Events.npl)의
// PktMon_FramePayload 정의에 적힌 필드를 선언된 순서와 폭 그대로 쌓는다. 아래 주석의 타입은
// 그 정의를 그대로 옮긴 것이다. 이렇게 하면 상수가 실제 배치와 어긋나는 순간 테스트가 깨진다.
func pktMonEvent(dirTag, packetType uint16, payload []byte) []byte {
	var b []byte
	b = binary.LittleEndian.AppendUint64(b, 0x1122334455667788)   // UINT64 PktGroupId
	b = binary.LittleEndian.AppendUint16(b, 7)                    // UINT16 PktNumber
	b = binary.LittleEndian.AppendUint16(b, 1)                    // UINT16 AppearanceCount
	b = binary.LittleEndian.AppendUint16(b, dirTag)               // UINT16 DirTag
	b = binary.LittleEndian.AppendUint16(b, packetType)           // UINT16 PacketType
	b = binary.LittleEndian.AppendUint16(b, 42)                   // UINT16 ComponentId
	b = binary.LittleEndian.AppendUint16(b, 3)                    // UINT16 EdgeId
	b = binary.LittleEndian.AppendUint16(b, 1)                    // UINT16 FilterId
	b = binary.LittleEndian.AppendUint32(b, 0)                    // UINT32 DropReason
	b = binary.LittleEndian.AppendUint32(b, 0)                    // UINT32 DropLocation
	b = binary.LittleEndian.AppendUint16(b, uint16(len(payload))) // UINT16 OriginalPayloadSize
	b = binary.LittleEndian.AppendUint16(b, uint16(len(payload))) // UINT16 LoggedPayloadSize
	return append(b, payload...)
}

func TestPktMonHeaderLayoutMatchesManifest(t *testing.T) {
	// 필드를 선언 순서대로 쌓은 결과와 우리가 박아 둔 오프셋이 같은 곳을 가리키는지 본다.
	// 이게 어긋나면 실기기에서 프레임이 전부 쓰레기가 되거나 조용히 0건이 된다.
	raw := pktMonEvent(pktMonDirTx, pktMonPayloadEthernet, []byte{0xaa, 0xbb, 0xcc})

	if got := len(raw) - 3; got != pktMonHeaderLen {
		t.Errorf("헤더 길이 = %d, pktMonHeaderLen = %d", got, pktMonHeaderLen)
	}
	if got := binary.LittleEndian.Uint16(raw[pktMonOffDirTag:]); got != pktMonDirTx {
		t.Errorf("pktMonOffDirTag(%d) 자리 값 = %d, 원하는 값 %d", pktMonOffDirTag, got, pktMonDirTx)
	}
	if got := binary.LittleEndian.Uint16(raw[pktMonOffPacketType:]); got != pktMonPayloadEthernet {
		t.Errorf("pktMonOffPacketType(%d) 자리 값 = %d", pktMonOffPacketType, got)
	}
	if got := binary.LittleEndian.Uint16(raw[pktMonOffLoggedSize:]); got != 3 {
		t.Errorf("pktMonOffLoggedSize(%d) 자리 값 = %d, 원하는 값 3", pktMonOffLoggedSize, got)
	}
}

func TestParsePktMonPacketExtractsFrame(t *testing.T) {
	payload := []byte{1, 2, 3, 4, 5}
	f, reject := parsePktMonPacket(pktMonEvent(pktMonDirTx, pktMonPayloadEthernet, payload))

	if reject != pktMonAccept {
		t.Fatalf("버렸다: %v", reject)
	}
	if f.DirTag != pktMonDirTx {
		t.Errorf("DirTag = %d", f.DirTag)
	}
	if f.PacketType != pktMonPayloadEthernet {
		t.Errorf("PacketType = %d", f.PacketType)
	}
	if !bytes.Equal(f.Payload, payload) {
		t.Errorf("Payload = %v, 원하는 값 %v", f.Payload, payload)
	}
}

func TestParsePktMonPacketRejectsShortEvent(t *testing.T) {
	// 헤더도 다 안 온 이벤트. 여기서 안 막으면 슬라이스 경계를 넘는다.
	for _, n := range []int{0, 1, pktMonHeaderLen - 1} {
		if _, reject := parsePktMonPacket(make([]byte, n)); reject != pktMonRejectShort {
			t.Errorf("%d 바이트 이벤트 = %v, short 여야 한다", n, reject)
		}
	}
}

func TestParsePktMonPacketRejectsEmptyPayload(t *testing.T) {
	// keyword 0x10(Payload)을 안 켜면 프레임 바이트 없이 메타데이터만 온다.
	// 그걸 조용히 넘기면 "세션도 프로바이더도 붙었는데 0건" 이 되어 원인을 못 찾는다.
	if _, reject := parsePktMonPacket(pktMonEvent(pktMonDirTx, pktMonPayloadEthernet, nil)); reject != pktMonRejectEmpty {
		t.Errorf("빈 payload = %v, empty 여야 한다", reject)
	}
}

func TestParsePktMonPacketRejectsSizeMismatch(t *testing.T) {
	// 우리가 잡은 오프셋이 이 Windows 판과 어긋나면 32번 자리에서 읽은 값이 프레임 길이일
	// 리가 없다. 그 어긋남을 잡는 것이 이 검사의 목적이다.
	base := pktMonEvent(pktMonDirTx, pktMonPayloadEthernet, []byte{1, 2, 3, 4})

	tooLong := append([]byte(nil), base...)
	binary.LittleEndian.PutUint16(tooLong[pktMonOffLoggedSize:], 4096)
	if _, reject := parsePktMonPacket(tooLong); reject != pktMonRejectSizeMismatch {
		t.Errorf("길이가 넘칠 때 = %v, sizeMismatch 여야 한다", reject)
	}

	// 뒤에 바이트가 남는 경우도 어긋남으로 본다.
	trailing := append(append([]byte(nil), base...), 0xff, 0xff)
	if _, reject := parsePktMonPacket(trailing); reject != pktMonRejectSizeMismatch {
		t.Errorf("뒤에 바이트가 남을 때 = %v, sizeMismatch 여야 한다", reject)
	}
}

func TestPktMonEthernetFrameKeepsEthernetAsIs(t *testing.T) {
	want := ipv4Frame(testSrcIP, testDstIP, tcpSegment(testSrcPrt, portHTTPS, []byte("hello")))
	f, reject := parsePktMonPacket(pktMonEvent(pktMonDirTx, pktMonPayloadEthernet, want))
	if reject != pktMonAccept {
		t.Fatalf("버렸다: %v", reject)
	}

	got, reject := pktMonEthernetFrame(f)
	if reject != pktMonAccept {
		t.Fatalf("이더넷 프레임을 버렸다: %v", reject)
	}
	if !bytes.Equal(got, want) {
		t.Error("이더넷 프레임은 손대지 않고 그대로 넘겨야 한다")
	}
}

func TestPktMonEthernetFrameWrapsRawIP(t *testing.T) {
	// pktmon 이 IP 헤더부터 주는 경우(PacketType == 3)다. 여기서 이더넷 헤더를 못 씌우면
	// packet.Parse 가 IP 헤더를 이더넷 헤더로 읽어 조용히 0건이 된다.
	//
	// 검사는 "우리가 만든 프레임이 우리 기대와 같은가" 가 아니라 "packet.Parse 가 실제로
	// 흐름을 뽑아내는가" 로 한다. 우리 기대끼리 견주면 양쪽이 같이 틀려도 통과한다.
	cases := []struct {
		name  string
		frame []byte
		want  packet.Flow
	}{
		{
			name:  "IPv4",
			frame: ipv4Frame(testSrcIP, testDstIP, tcpSegment(testSrcPrt, portHTTPS, []byte("x"))),
			want: packet.Flow{
				SrcIP: testSrcIP, DstIP: testDstIP,
				SrcPort: testSrcPrt, DstPort: portHTTPS, Protocol: "tcp",
			},
		},
		{
			name:  "IPv6",
			frame: ipv6Frame("2001:db8::1", "2001:db8::2", tcpSegment(testSrcPrt, portHTTPS, []byte("x"))),
			want: packet.Flow{
				SrcIP: "2001:db8::1", DstIP: "2001:db8::2",
				SrcPort: testSrcPrt, DstPort: portHTTPS, Protocol: "tcp",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// 이더넷 헤더를 떼어 raw IP 프레임을 만든다. pktmon 이 PacketType 3 으로 주는 모양이다.
			rawIP := tc.frame[etherHeaderLen:]

			f, reject := parsePktMonPacket(pktMonEvent(pktMonDirTx, pktMonPayloadIP, rawIP))
			if reject != pktMonAccept {
				t.Fatalf("버렸다: %v", reject)
			}
			got, reject := pktMonEthernetFrame(f)
			if reject != pktMonAccept {
				t.Fatalf("raw IP 프레임을 버렸다: %v", reject)
			}

			flow, payload, ok := packet.Parse(got, packet.LinkEthernet)
			if !ok {
				t.Fatalf("packet.Parse 가 못 읽었다: %x", got)
			}
			if flow != tc.want {
				t.Errorf("흐름 = %+v, 원하는 값 %+v", flow, tc.want)
			}
			if string(payload) != "x" {
				t.Errorf("페이로드 = %q", payload)
			}
		})
	}
}

func TestPktMonEthernetFrameRejectsUnusableTypes(t *testing.T) {
	// WiFi 는 802.11 프레임이라 packet.Parse 가 다루지 못한다. Unknown 도 마찬가지다.
	// 조용히 넘기지 않고 이유를 남기며 버려야 실기기에서 원인을 좁힐 수 있다.
	for _, pt := range []uint16{pktMonPayloadUnknown, pktMonPayloadWiFi, 99} {
		f, reject := parsePktMonPacket(pktMonEvent(pktMonDirTx, pt, []byte{0x45, 0, 0, 20}))
		if reject != pktMonAccept {
			t.Fatalf("파싱에서 버렸다: %v", reject)
		}
		if _, reject := pktMonEthernetFrame(f); reject != pktMonRejectLinkType {
			t.Errorf("PacketType %d = %v, linkType 여야 한다", pt, reject)
		}
	}
}

func TestPktMonEthernetFrameRejectsNonIPRawPayload(t *testing.T) {
	// PacketType 이 IP 라는데 첫 니블이 4 도 6 도 아니면 우리가 무언가 잘못 읽은 것이다.
	f, reject := parsePktMonPacket(pktMonEvent(pktMonDirTx, pktMonPayloadIP, []byte{0x00, 0x11, 0x22}))
	if reject != pktMonAccept {
		t.Fatalf("파싱에서 버렸다: %v", reject)
	}
	if _, reject := pktMonEthernetFrame(f); reject != pktMonRejectLinkType {
		t.Errorf("IP 가 아닌 raw payload = %v, linkType 여야 한다", reject)
	}
}

func TestPktMonEthernetFrameCopiesPayload(t *testing.T) {
	// ETW 콜백이 주는 버퍼는 곧 덮어써진다. 복사하지 않고 채널로 넘기면 센서가 읽을 때쯤에는
	// 다른 패킷의 바이트가 들어 있다. 찾기 어려운 종류의 고장이라 여기서 못 박아 둔다.
	raw := pktMonEvent(pktMonDirTx, pktMonPayloadEthernet,
		ipv4Frame(testSrcIP, testDstIP, tcpSegment(testSrcPrt, portHTTPS, []byte("keep"))))

	f, _ := parsePktMonPacket(raw)
	frame, reject := pktMonEthernetFrame(f)
	if reject != pktMonAccept {
		t.Fatalf("버렸다: %v", reject)
	}
	before := append([]byte(nil), frame...)

	// 원본 버퍼를 통째로 덮어쓴다. ETW 가 버퍼를 재사용하는 것과 같은 일이다.
	for i := range raw {
		raw[i] = 0xff
	}
	if !bytes.Equal(frame, before) {
		t.Error("원본 버퍼가 바뀌자 프레임도 바뀌었다. 복사하지 않고 넘기고 있다")
	}
}

func TestPktMonInboundKnowsDirections(t *testing.T) {
	inbound := []uint16{pktMonDirIn, pktMonDirRx, pktMonDirIngress}
	outbound := []uint16{pktMonDirOut, pktMonDirTx, pktMonDirEgress}

	for _, d := range inbound {
		if !pktMonInbound(d) {
			t.Errorf("DirTag %d 는 들어오는 쪽이다", d)
		}
	}
	for _, d := range outbound {
		if pktMonInbound(d) {
			t.Errorf("DirTag %d 는 나가는 쪽이다", d)
		}
	}
	// 모르는 값은 통과시켜야 한다. 반대로 만들면 Windows 판이 우리가 모르는 태그를 쓰는 순간
	// 모든 프레임이 조용히 사라진다.
	for _, d := range []uint16{pktMonDirUnspecified, 7, 999} {
		if pktMonInbound(d) {
			t.Errorf("모르는 DirTag %d 를 들어오는 쪽으로 봤다. 통과시켜야 한다", d)
		}
	}
}

func TestPktMonStatsCountsAndReports(t *testing.T) {
	var s pktMonStats
	s.count(pktMonAccept)
	s.count(pktMonRejectSizeMismatch)
	s.count(pktMonRejectSizeMismatch)
	s.observe(pktMonFrame{PacketType: pktMonPayloadEthernet, DirTag: pktMonDirTx})

	args := s.logArgs()
	got := map[string]any{}
	for i := 0; i+1 < len(args); i += 2 {
		key, _ := args[i].(string)
		got[key] = args[i+1]
	}

	if got["accept"] != uint64(1) {
		t.Errorf("accept = %v", got["accept"])
	}
	if got["sizeMismatch"] != uint64(2) {
		t.Errorf("sizeMismatch = %v", got["sizeMismatch"])
	}
	if got["packetType1"] != uint64(1) {
		t.Errorf("packetType1 = %v", got["packetType1"])
	}
	if got["dirTag4"] != uint64(1) {
		t.Errorf("dirTag4 = %v", got["dirTag4"])
	}
	// 0 인 이유는 로그를 어지럽히기만 한다. 다만 accept 는 0 이어도 남아야 한다.
	if _, ok := got["inbound"]; ok {
		t.Error("한 번도 안 센 이유가 로그에 들어갔다")
	}

	var empty pktMonStats
	emptyArgs := empty.logArgs()
	if len(emptyArgs) != 2 || emptyArgs[0] != "accept" || emptyArgs[1] != uint64(0) {
		t.Errorf("아무것도 안 셌을 때 = %v, accept=0 은 반드시 남아야 한다", emptyArgs)
	}
}

func TestPktMonCommandArgs(t *testing.T) {
	// 필터를 빠뜨리면 그 기기의 모든 패킷이 ETW 로 올라온다. 인자 하나가 빠지는 것이
	// 실기기에서 부하 사고로 이어지는 자리라 모양을 못 박아 둔다.
	wantFilter := []string{"filter", "add", "EDRdog-TLS", "-t", "TCP", "-p", "443"}
	if got := pktMonFilterArgs(portHTTPS); !equalStrings(got, wantFilter) {
		t.Errorf("필터 인자 = %v, 원하는 값 %v", got, wantFilter)
	}

	start := pktMonStartArgs(CaptureSnapLen, `C:\Temp\x.etl`)
	// --pkt-size 기본값 128 로는 ClientHello 의 SNI 확장이 잘려 도메인을 못 뽑는다.
	if !hasArgPair(start, "--pkt-size", "2048") {
		t.Errorf("--pkt-size 2048 이 없다: %v", start)
	}
	// keyword 만 켜고 --flags 에서 raw packet 을 빼면 프레임 바이트가 안 온다.
	if !hasArgPair(start, "--flags", "0x10") {
		t.Errorf("--flags 0x10 이 없다: %v", start)
	}
	if !hasArgPair(start, "--comp", "nics") {
		t.Errorf("--comp nics 가 없다: %v", start)
	}
	if !hasArgPair(start, "--file-name", `C:\Temp\x.etl`) {
		t.Errorf("--file-name 이 없다: %v", start)
	}
}

func TestPktMonProviderSpecCarriesPayloadKeyword(t *testing.T) {
	// keyword 0x10(Payload)이 빠지면 이벤트 160 이 한 건도 오지 않는다.
	// 이벤트 ID 를 적어 두면 설정/랜다운 이벤트가 커널에서 걸린다.
	want := "Microsoft-Windows-PktMon:0xff:160:0x10"
	if got := pktMonProviderSpec(); got != want {
		t.Errorf("프로바이더 설정 = %q, 원하는 값 %q", got, want)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func hasArgPair(args []string, flag, value string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == value {
			return true
		}
	}
	return false
}
