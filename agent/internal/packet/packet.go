// Package packet 은 캡처한 프레임에서 메타데이터만 뽑는다. 원본 바이트는 어떤 구조체에도 담지 않는다.
//
// 입력은 신뢰할 수 없는 바이트다. 어떤 입력에도 panic 하지 않고 false 를 돌려주는 것이 이 패키지의 계약이다.
package packet

import (
	"encoding/binary"
	"net"
)

// LinkType 은 프레임이 어느 계층부터 시작하는지다. 패킷만 보고는 알 수 없어 호출자가 알려준다.
type LinkType int

const (
	// LinkEthernet 은 이더넷 헤더로 시작하는 프레임이다.
	LinkEthernet LinkType = iota
	// LinkRawIP 는 IP 헤더로 바로 시작하는 프레임이다.
	LinkRawIP
)

// Flow 는 패킷의 4-튜플이다. 어느 연결에 속한 패킷인지 가린다.
type Flow struct {
	SrcIP, DstIP     string
	SrcPort, DstPort int
	Protocol         string // "tcp" 또는 "udp"
}

const (
	etherTypeIPv4 = 0x0800
	etherTypeIPv6 = 0x86dd

	protoTCP      = 6
	protoUDP      = 17
	protoHopByHop = 0
	protoRouting  = 43
	protoFragment = 44
	protoNoNext   = 59
	protoDestOpts = 60
)

// maxExtHeaders 는 IPv6 확장 헤더를 몇 개까지 벗길지다.
// 상한이 없으면 조작된 패킷이 확장 헤더 사슬을 길게 늘려 CPU 를 태울 수 있다.
const maxExtHeaders = 8

// Parse 는 프레임에서 4-튜플과 전송 계층 페이로드를 꺼낸다.
// 페이로드는 원본 프레임을 가리키는 슬라이스라 오래 쥐고 있으면 안 된다.
func Parse(frame []byte, linkType LinkType) (Flow, []byte, bool) {
	if linkType == LinkEthernet {
		if len(frame) < 14 {
			return Flow{}, nil, false
		}
		switch binary.BigEndian.Uint16(frame[12:14]) {
		case etherTypeIPv4, etherTypeIPv6:
			frame = frame[14:]
		default:
			// ARP, VLAN 태그 등. 우리가 볼 것이 없다.
			return Flow{}, nil, false
		}
	}
	if len(frame) == 0 {
		return Flow{}, nil, false
	}

	// IP 버전은 첫 바이트 상위 4비트다. raw IP 캡처에는 이것 말고 단서가 없다.
	switch frame[0] >> 4 {
	case 4:
		return parseIPv4(frame)
	case 6:
		return parseIPv6(frame)
	}
	return Flow{}, nil, false
}

func parseIPv4(b []byte) (Flow, []byte, bool) {
	if len(b) < 20 {
		return Flow{}, nil, false
	}
	// 헤더 길이는 IHL 필드에서 읽는다. 20 으로 고정하면 옵션이 붙은 패킷에서 한 칸씩 어긋난다.
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || ihl > len(b) {
		return Flow{}, nil, false
	}

	// 첫 조각이 아닌 프래그먼트에는 전송 계층 헤더가 없다. 재조립은 하지 않는다.
	if binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
		return Flow{}, nil, false
	}

	// 전체 길이가 캡처 길이보다 짧으면 뒤는 패딩이다. 길면 잘린 패킷이니 있는 만큼만 본다.
	body := b[ihl:]
	if total := int(binary.BigEndian.Uint16(b[2:4])); total >= ihl && total <= len(b) {
		body = b[ihl:total]
	}

	src := net.IP(b[12:16]).String()
	dst := net.IP(b[16:20]).String()
	return parseTransport(b[9], src, dst, body)
}

func parseIPv6(b []byte) (Flow, []byte, bool) {
	if len(b) < 40 {
		return Flow{}, nil, false
	}
	src := net.IP(b[8:24]).String()
	dst := net.IP(b[24:40]).String()

	body := b[40:]
	if payloadLen := int(binary.BigEndian.Uint16(b[4:6])); payloadLen <= len(body) {
		body = body[:payloadLen]
	}

	next := b[6]
	for range maxExtHeaders {
		switch next {
		case protoHopByHop, protoRouting, protoDestOpts:
			// 확장 헤더는 [다음 헤더][길이] 로 시작하고 길이는 8바이트 단위에서 1을 뺀 값이다.
			if len(body) < 8 {
				return Flow{}, nil, false
			}
			extLen := (int(body[1]) + 1) * 8
			if extLen > len(body) {
				return Flow{}, nil, false
			}
			next, body = body[0], body[extLen:]
		case protoFragment:
			if len(body) < 8 {
				return Flow{}, nil, false
			}
			// 첫 조각이 아니면 전송 계층 헤더가 없다. IPv4 와 같은 판단이다.
			if binary.BigEndian.Uint16(body[2:4])&0xfff8 != 0 {
				return Flow{}, nil, false
			}
			next, body = body[0], body[8:]
		case protoNoNext:
			return Flow{}, nil, false
		default:
			return parseTransport(next, src, dst, body)
		}
	}
	return Flow{}, nil, false
}

func parseTransport(proto byte, src, dst string, b []byte) (Flow, []byte, bool) {
	switch proto {
	case protoTCP:
		if len(b) < 20 {
			return Flow{}, nil, false
		}
		// TCP 도 헤더 길이가 가변이다. 데이터 오프셋을 읽지 않으면 옵션이 페이로드로 섞인다.
		off := int(b[12]>>4) * 4
		if off < 20 || off > len(b) {
			return Flow{}, nil, false
		}
		return flowOf("tcp", src, dst, b), b[off:], true
	case protoUDP:
		if len(b) < 8 {
			return Flow{}, nil, false
		}
		payload := b[8:]
		if l := int(binary.BigEndian.Uint16(b[4:6])); l >= 8 && l <= len(b) {
			payload = b[8:l]
		}
		return flowOf("udp", src, dst, b), payload, true
	}
	return Flow{}, nil, false
}

// flowOf 는 전송 계층 헤더 앞 4바이트에서 포트를 읽는다. TCP 와 UDP 가 같은 자리다.
func flowOf(proto, src, dst string, b []byte) Flow {
	return Flow{
		SrcIP:    src,
		DstIP:    dst,
		SrcPort:  int(binary.BigEndian.Uint16(b[0:2])),
		DstPort:  int(binary.BigEndian.Uint16(b[2:4])),
		Protocol: proto,
	}
}
