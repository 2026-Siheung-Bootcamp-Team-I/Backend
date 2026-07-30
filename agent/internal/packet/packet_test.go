package packet

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// 아래 헬퍼들은 실제 형식 그대로 프레임을 만든다. 손으로 적은 16진수 덩어리보다 무엇을
// 바꿨는지 읽히고, 헤더 길이 계산이 테스트 쪽에서 틀릴 여지가 적다.

func ethernet(etherType uint16, body []byte) []byte {
	h := make([]byte, 14)
	copy(h[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})  // 목적지 MAC
	copy(h[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}) // 출발지 MAC
	binary.BigEndian.PutUint16(h[12:14], etherType)
	return append(h, body...)
}

func ipv4(proto byte, src, dst string, opts, body []byte) []byte {
	if len(opts)%4 != 0 {
		panic("IPv4 옵션은 4바이트 배수여야 한다")
	}
	ihl := 20 + len(opts)
	h := make([]byte, ihl)
	h[0] = 4<<4 | byte(ihl/4)
	binary.BigEndian.PutUint16(h[2:4], uint16(ihl+len(body)))
	h[8] = 64 // TTL
	h[9] = proto
	copy(h[12:16], net.ParseIP(src).To4())
	copy(h[16:20], net.ParseIP(dst).To4())
	copy(h[20:], opts)
	return append(h, body...)
}

func ipv6(next byte, src, dst string, body []byte) []byte {
	h := make([]byte, 40)
	h[0] = 6 << 4
	binary.BigEndian.PutUint16(h[4:6], uint16(len(body)))
	h[6] = next
	h[7] = 64 // hop limit
	copy(h[8:24], net.ParseIP(src).To16())
	copy(h[24:40], net.ParseIP(dst).To16())
	return append(h, body...)
}

func tcp(srcPort, dstPort int, opts, payload []byte) []byte {
	if len(opts)%4 != 0 {
		panic("TCP 옵션은 4바이트 배수여야 한다")
	}
	off := 20 + len(opts)
	h := make([]byte, off)
	binary.BigEndian.PutUint16(h[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(h[2:4], uint16(dstPort))
	h[12] = byte(off/4) << 4
	h[13] = 0x18 // PSH|ACK
	copy(h[20:], opts)
	return append(h, payload...)
}

func udp(srcPort, dstPort int, payload []byte) []byte {
	h := make([]byte, 8)
	binary.BigEndian.PutUint16(h[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(h[2:4], uint16(dstPort))
	binary.BigEndian.PutUint16(h[4:6], uint16(8+len(payload)))
	return append(h, payload...)
}

func TestParseIPv4TCPOverEthernet(t *testing.T) {
	want := []byte("hello")
	frame := ethernet(etherTypeIPv4, ipv4(protoTCP, "192.0.2.10", "203.0.113.5", nil, tcp(54321, 443, nil, want)))

	flow, payload, ok := Parse(frame, LinkEthernet)
	if !ok {
		t.Fatal("Parse 가 false 를 돌려줬다")
	}
	wantFlow := Flow{SrcIP: "192.0.2.10", DstIP: "203.0.113.5", SrcPort: 54321, DstPort: 443, Protocol: "tcp"}
	if flow != wantFlow {
		t.Errorf("flow = %+v, want %+v", flow, wantFlow)
	}
	if !bytes.Equal(payload, want) {
		t.Errorf("payload = %q, want %q", payload, want)
	}
}

func TestParseIPv6UDPRawIP(t *testing.T) {
	want := []byte("query")
	frame := ipv6(protoUDP, "2001:db8::1", "2001:db8::2", udp(51000, 53, want))

	flow, payload, ok := Parse(frame, LinkRawIP)
	if !ok {
		t.Fatal("Parse 가 false 를 돌려줬다")
	}
	wantFlow := Flow{SrcIP: "2001:db8::1", DstIP: "2001:db8::2", SrcPort: 51000, DstPort: 53, Protocol: "udp"}
	if flow != wantFlow {
		t.Errorf("flow = %+v, want %+v", flow, wantFlow)
	}
	if !bytes.Equal(payload, want) {
		t.Errorf("payload = %q, want %q", payload, want)
	}
}

// IHL 을 20 으로 고정하면 옵션이 붙은 순간 포트가 옵션 바이트에서 읽혀 엉뚱한 값이 나온다.
func TestParseIPv4WithOptions(t *testing.T) {
	opts := []byte{0x94, 0x04, 0x00, 0x00} // Router Alert, 4바이트
	want := []byte("payload")
	frame := ipv4(protoTCP, "198.51.100.1", "203.0.113.9", opts, tcp(1234, 8443, nil, want))

	if frame[0]&0x0f == 5 {
		t.Fatal("IHL 이 5 다. 옵션이 붙은 패킷을 만들지 못했다")
	}

	flow, payload, ok := Parse(frame, LinkRawIP)
	if !ok {
		t.Fatal("Parse 가 false 를 돌려줬다")
	}
	if flow.SrcPort != 1234 || flow.DstPort != 8443 {
		t.Errorf("포트 = %d -> %d, want 1234 -> 8443", flow.SrcPort, flow.DstPort)
	}
	if !bytes.Equal(payload, want) {
		t.Errorf("payload = %q, want %q", payload, want)
	}
}

// TCP 옵션도 마찬가지다. 데이터 오프셋을 안 읽으면 옵션이 페이로드 앞에 섞여 들어온다.
func TestParseTCPWithOptions(t *testing.T) {
	opts := []byte{0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x04, 0x02} // MSS, NOP, NOP, SACK 허용
	want := []byte("body")
	frame := ipv4(protoTCP, "192.0.2.1", "192.0.2.2", nil, tcp(80, 80, opts, want))

	_, payload, ok := Parse(frame, LinkRawIP)
	if !ok {
		t.Fatal("Parse 가 false 를 돌려줬다")
	}
	if !bytes.Equal(payload, want) {
		t.Errorf("payload = %q, want %q", payload, want)
	}
}

func TestParseIPv6ExtensionHeaders(t *testing.T) {
	want := []byte("dns")
	inner := udp(5353, 53, want)

	// Fragment 헤더(첫 조각): [다음 헤더][예약][오프셋 2바이트][식별자 4바이트]
	frag := make([]byte, 8)
	frag[0] = protoUDP
	frag = append(frag, inner...)

	// Hop-by-Hop 헤더: [다음 헤더][길이][옵션...], 길이는 8바이트 단위에서 1을 뺀 값
	hop := make([]byte, 8)
	hop[0] = protoFragment
	hop[1] = 0
	hop = append(hop, frag...)

	frame := ipv6(protoHopByHop, "2001:db8::a", "2001:db8::b", hop)

	flow, payload, ok := Parse(frame, LinkRawIP)
	if !ok {
		t.Fatal("확장 헤더를 벗기지 못했다")
	}
	if flow.DstPort != 53 || flow.Protocol != "udp" {
		t.Errorf("flow = %+v, want udp/53", flow)
	}
	if !bytes.Equal(payload, want) {
		t.Errorf("payload = %q, want %q", payload, want)
	}
}

func TestParseEmptyPayload(t *testing.T) {
	frame := ipv4(protoTCP, "192.0.2.1", "203.0.113.1", nil, tcp(1000, 443, nil, nil))

	flow, payload, ok := Parse(frame, LinkRawIP)
	if !ok {
		t.Fatal("페이로드가 비었다고 false 를 주면 안 된다. 흐름은 유효하다")
	}
	if len(payload) != 0 {
		t.Errorf("payload = %q, want 빈 슬라이스", payload)
	}
	if flow.DstPort != 443 {
		t.Errorf("DstPort = %d, want 443", flow.DstPort)
	}
}

// 길이 필드는 공격자가 정하는 값이다. 실제 프레임보다 크다고 그만큼 읽으면 범위를 넘는다.
func TestParseLengthFieldsLargerThanFrame(t *testing.T) {
	want := []byte("short")

	t.Run("IPv4 total length", func(t *testing.T) {
		frame := ipv4(protoUDP, "192.0.2.1", "203.0.113.1", nil, udp(1000, 53, want))
		binary.BigEndian.PutUint16(frame[2:4], 60000)

		_, payload, ok := Parse(frame, LinkRawIP)
		if !ok {
			t.Fatal("있는 만큼은 읽어야 한다")
		}
		if !bytes.Equal(payload, want) {
			t.Errorf("payload = %q, want %q", payload, want)
		}
	})

	t.Run("UDP length", func(t *testing.T) {
		frame := ipv4(protoUDP, "192.0.2.1", "203.0.113.1", nil, udp(1000, 53, want))
		binary.BigEndian.PutUint16(frame[20+4:20+6], 60000)

		_, payload, ok := Parse(frame, LinkRawIP)
		if !ok {
			t.Fatal("있는 만큼은 읽어야 한다")
		}
		if !bytes.Equal(payload, want) {
			t.Errorf("payload = %q, want %q", payload, want)
		}
	})

	t.Run("IPv6 payload length", func(t *testing.T) {
		frame := ipv6(protoUDP, "2001:db8::1", "2001:db8::2", udp(1000, 53, want))
		binary.BigEndian.PutUint16(frame[4:6], 60000)

		_, payload, ok := Parse(frame, LinkRawIP)
		if !ok {
			t.Fatal("있는 만큼은 읽어야 한다")
		}
		if !bytes.Equal(payload, want) {
			t.Errorf("payload = %q, want %q", payload, want)
		}
	})

	t.Run("TCP data offset", func(t *testing.T) {
		frame := ipv4(protoTCP, "192.0.2.1", "203.0.113.1", nil, tcp(1000, 443, nil, want))
		frame[20+12] = 0xf0 // 데이터 오프셋 15 = 60바이트, 실제 헤더보다 훨씬 크다

		if _, _, ok := Parse(frame, LinkRawIP); ok {
			t.Error("헤더가 프레임을 넘어가는데 true 를 줬다")
		}
	})

	t.Run("IPv6 확장 헤더 길이", func(t *testing.T) {
		hop := []byte{protoUDP, 200, 0, 0, 0, 0, 0, 0}
		frame := ipv6(protoHopByHop, "2001:db8::1", "2001:db8::2", hop)

		if _, _, ok := Parse(frame, LinkRawIP); ok {
			t.Error("확장 헤더가 프레임을 넘어가는데 true 를 줬다")
		}
	})
}

// 잘린 패킷은 캡처에서 늘 나온다. 어느 지점에서 잘려도 panic 하면 안 된다.
func TestParseTruncatedNeverPanics(t *testing.T) {
	frames := map[string][]byte{
		"ipv4/tcp": ethernet(etherTypeIPv4, ipv4(protoTCP, "192.0.2.1", "203.0.113.1", nil, tcp(1000, 443, nil, []byte("abcdefgh")))),
		"ipv6/udp": ethernet(etherTypeIPv6, ipv6(protoUDP, "2001:db8::1", "2001:db8::2", udp(1000, 53, []byte("abcdefgh")))),
	}
	for name, frame := range frames {
		t.Run(name, func(t *testing.T) {
			for i := range len(frame) + 1 {
				Parse(frame[:i], LinkEthernet)
				Parse(frame[:i], LinkRawIP)
			}
		})
	}
}

func TestParseHeaderTooShort(t *testing.T) {
	cases := map[string][]byte{
		"빈 프레임":      {},
		"이더넷 헤더만":    ethernet(etherTypeIPv4, nil),
		"IPv4 헤더 미달": ipv4(protoTCP, "192.0.2.1", "203.0.113.1", nil, nil)[:19],
		"IPv6 헤더 미달": ipv6(protoUDP, "2001:db8::1", "2001:db8::2", nil)[:39],
		"TCP 헤더 미달":  ipv4(protoTCP, "192.0.2.1", "203.0.113.1", nil, make([]byte, 19)),
		"UDP 헤더 미달":  ipv4(protoUDP, "192.0.2.1", "203.0.113.1", nil, make([]byte, 7)),
		"IHL 이 5 보다 작음": func() []byte {
			f := ipv4(protoTCP, "192.0.2.1", "203.0.113.1", nil, tcp(1, 2, nil, nil))
			f[0] = 4<<4 | 4
			return f
		}(),
	}
	for name, frame := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, ok := Parse(frame, LinkRawIP); ok {
				t.Error("길이가 모자란 패킷에 true 를 줬다")
			}
		})
	}
}

func TestParseIgnoresUninterestingFrames(t *testing.T) {
	body := ipv4(protoTCP, "192.0.2.1", "203.0.113.1", nil, tcp(1, 443, nil, nil))
	cases := map[string][]byte{
		"ARP 이더타입": ethernet(0x0806, body),
		"VLAN 태그":  ethernet(0x8100, body),
	}
	for name, frame := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, ok := Parse(frame, LinkEthernet); ok {
				t.Error("IP 가 아닌 프레임에 true 를 줬다")
			}
		})
	}

	t.Run("ICMP", func(t *testing.T) {
		frame := ipv4(1, "192.0.2.1", "203.0.113.1", nil, make([]byte, 40))
		if _, _, ok := Parse(frame, LinkRawIP); ok {
			t.Error("TCP/UDP 가 아닌데 true 를 줬다")
		}
	})
}

// 첫 조각이 아닌 프래그먼트에는 전송 계층 헤더가 없다. 재조립하지 않으니 버려야 한다.
func TestParseSkipsNonFirstFragments(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		frame := ipv4(protoTCP, "192.0.2.1", "203.0.113.1", nil, make([]byte, 40))
		binary.BigEndian.PutUint16(frame[6:8], 185) // 오프셋 185 (1480바이트째)

		if _, _, ok := Parse(frame, LinkRawIP); ok {
			t.Error("중간 조각에 true 를 줬다")
		}
	})

	t.Run("IPv6", func(t *testing.T) {
		frag := make([]byte, 8)
		frag[0] = protoUDP
		binary.BigEndian.PutUint16(frag[2:4], 1480) // 오프셋이 0 이 아님
		frag = append(frag, make([]byte, 40)...)
		frame := ipv6(protoFragment, "2001:db8::1", "2001:db8::2", frag)

		if _, _, ok := Parse(frame, LinkRawIP); ok {
			t.Error("중간 조각에 true 를 줬다")
		}
	})
}

// IPv4 매핑 주소나 축약형이 섞이면 같은 목적지가 여러 문자열로 갈린다.
func TestParseNormalizesAddresses(t *testing.T) {
	frame := ipv6(protoTCP, "2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::2", tcp(1, 443, nil, nil))

	flow, _, ok := Parse(frame, LinkRawIP)
	if !ok {
		t.Fatal("Parse 가 false 를 돌려줬다")
	}
	if flow.SrcIP != "2001:db8::1" {
		t.Errorf("SrcIP = %q, want 2001:db8::1", flow.SrcIP)
	}
}
