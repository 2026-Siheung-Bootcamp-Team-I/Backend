package packet

import (
	"crypto/tls"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// FuzzParse 는 임의 바이트를 파서 전부에 먹여 panic 하지 않는지 본다.
//
// 이 패키지의 입력은 네트워크에서 온다. 길이 필드를 마음대로 적은 패킷 한 장으로 에이전트가
// 죽으면 그건 보안 도구가 아니라 공격 표면이다. 표 기반 테스트는 우리가 떠올린 모양만 보지만
// 퍼즈는 떠올리지 못한 조합을 찾는다. 경계 검사 한 군데를 빠뜨리면 여기서 걸린다.
//
// 시드는 실제 형식의 프레임이다. 퍼저가 여기서 한 바이트씩 비틀며 길이 필드를 헤집는다.
func FuzzParse(f *testing.F) {
	f.Add(ethernet(etherTypeIPv4, ipv4(protoTCP, "192.0.2.1", "203.0.113.1", nil, tcp(1000, 443, nil, []byte("payload")))), true)
	f.Add(ethernet(etherTypeIPv6, ipv6(protoUDP, "2001:db8::1", "2001:db8::2", udp(1000, 53, []byte("payload")))), true)
	f.Add(ipv4(protoUDP, "192.0.2.1", "203.0.113.1", nil, udp(51000, 53, dnsQuery(f, "www.example.com.", dnsmessage.TypeA))), false)
	f.Add(ipv6(protoTCP, "2001:db8::1", "2001:db8::2", tcp(52000, 443, nil, clientHello(f, &tls.Config{ServerName: "example.com"}))), false)
	f.Add(clientHello(f, &tls.Config{ServerName: "example.com"}), false)
	f.Add(dnsQuery(f, "www.example.com.", dnsmessage.TypeA), false)
	f.Add([]byte{}, false)

	f.Fuzz(func(t *testing.T, data []byte, ethernetLink bool) {
		link := LinkRawIP
		if ethernetLink {
			link = LinkEthernet
		}

		// 프레임 자체를 상위 파서에 그대로 먹인다. 캡처가 어긋나 엉뚱한 바이트가 들어오는 경우다.
		ParseDNS(data)
		ParseClientHello(data)

		// 조립기는 상태를 들고 이어 붙이는 코드라 더 위험하다. 조각난 입력을 그대로 먹인다.
		asm := NewAssembler()
		asm.Push(Flow{Protocol: "tcp", DstPort: 443}, data, time.Unix(1785400000, 0))

		flow, payload, ok := Parse(data, link)
		if !ok {
			return
		}
		if flow.Protocol != "tcp" && flow.Protocol != "udp" {
			t.Fatalf("true 인데 프로토콜이 %q 다", flow.Protocol)
		}
		if flow.SrcIP == "" || flow.DstIP == "" {
			t.Fatalf("true 인데 주소가 비었다: %+v", flow)
		}

		// 실제 경로: 벗겨 낸 페이로드가 그대로 다음 파서로 간다.
		ParseDNS(payload)
		ParseClientHello(payload)
		asm.Push(flow, payload, time.Unix(1785400000, 0))
	})
}
