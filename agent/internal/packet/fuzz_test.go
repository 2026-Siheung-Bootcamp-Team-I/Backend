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

// FuzzAssembler 는 조각난 입력을 조립기에 이어 먹여 panic 하지 않는지 본다.
//
// FuzzParse 와 따로 두는 이유는 위험한 부분이 다르기 때문이다. 파서는 바이트 한 장을 보지만
// 조립기는 여러 번의 Push 에 걸쳐 상태를 들고 있다. 버퍼를 이어 붙이는 자리, 흐름을 지우는
// 자리, 만료를 판정하는 자리가 서로 어긋나면 거기서 깨진다. 그래서 한 입력을 여러 조각으로
// 나눠 넣고, 시각도 앞뒤로 움직여 만료 경로까지 지나가게 한다.
func FuzzAssembler(f *testing.F) {
	hello := clientHello(f, &tls.Config{ServerName: "example.com"})
	f.Add(hello, uint8(200), uint8(0))
	f.Add(hello, uint8(1), uint8(11)) // 조각을 잘게 내고 중간에 TTL 을 넘긴다
	f.Add([]byte{recordHandshake, 3, 1, 0xff, 0xff, 1}, uint8(3), uint8(0))
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"), uint8(4), uint8(1))
	f.Add([]byte{}, uint8(1), uint8(0))

	f.Fuzz(func(t *testing.T, data []byte, chunk uint8, skewSeconds uint8) {
		a := NewAssembler()
		base := time.Unix(1785400000, 0)
		flow := Flow{Protocol: "tcp", SrcIP: "10.0.0.2", SrcPort: 51000, DstIP: "93.184.216.34", DstPort: 443}

		size := int(chunk)
		if size == 0 {
			size = 1
		}
		for i, step := 0, 0; i < len(data); i, step = i+size, step+1 {
			end := min(i+size, len(data))
			// 조각마다 시계를 앞으로 민다. skew 가 크면 TTL 을 넘겨 만료 경로를 지난다.
			now := base.Add(time.Duration(step) * time.Duration(skewSeconds) * time.Second)
			if hello, ok := a.Push(flow, data[i:end], now); ok {
				// 완성했다고 했으면 그 흐름은 즉시 사라져야 한다. 남으면 재전송에서 또 나온다.
				if a.Len() != 0 {
					t.Fatalf("완성 후에도 흐름이 %d 개 남았다 (SNI=%q)", a.Len(), hello.SNI)
				}
			}
			if a.Len() > assemblerMaxFlows {
				t.Fatalf("추적 흐름이 %d 개다. 상한 %d", a.Len(), assemblerMaxFlows)
			}
		}
	})
}
