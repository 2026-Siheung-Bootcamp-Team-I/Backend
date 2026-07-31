package sensor

import (
	"encoding/binary"
	"net"
	"testing"

	"golang.org/x/net/bpf"
)

// captureVM 은 CaptureFilter 가 만든 바이트코드를 그대로 돌려 보는 가상 머신이다.
//
// 조립한 뒤 다시 역어셈블해서 넣는 이유는 커널이 받는 것과 같은 바이트코드를 검증하기
// 위해서다. bpf.Instruction 을 바로 VM 에 넣으면 조립 과정의 실수는 걸러지지 않는다.
func captureVM(t *testing.T) *bpf.VM {
	t.Helper()

	raw, err := CaptureFilter()
	if err != nil {
		t.Fatalf("CaptureFilter: %v", err)
	}
	insts, ok := bpf.Disassemble(raw)
	if !ok {
		t.Fatal("조립된 프로그램을 다시 역어셈블하지 못했다")
	}
	vm, err := bpf.NewVM(insts)
	if err != nil {
		t.Fatalf("bpf.NewVM: %v", err)
	}
	return vm
}

func TestCaptureFilter(t *testing.T) {
	vm := captureVM(t)

	dns := []byte("dns-payload")
	tls := []byte("tls-payload")

	tests := []struct {
		name  string
		frame []byte
		want  bool
	}{
		{
			name:  "IPv4 DNS 질의는 통과한다",
			frame: ipv4Frame("10.0.0.5", "1.1.1.1", udpSegment(51000, 53, dns)),
			want:  true,
		},
		{
			name:  "IPv4 DNS 응답도 통과한다. 응답을 봐야 어느 IP 로 풀렸는지 안다",
			frame: ipv4Frame("1.1.1.1", "10.0.0.5", udpSegment(53, 51000, dns)),
			want:  true,
		},
		{
			name:  "IPv4 TCP 443 나가는 패킷은 통과한다",
			frame: ipv4Frame("10.0.0.5", "93.184.216.34", tcpSegment(51000, 443, tls)),
			want:  true,
		},
		{
			name:  "IPv4 TCP 443 들어오는 패킷은 거른다. ClientHello 만 필요하다",
			frame: ipv4Frame("93.184.216.34", "10.0.0.5", tcpSegment(443, 51000, tls)),
			want:  false,
		},
		{
			name:  "IPv4 TCP 80 은 통과한다. 평문 HTTP 는 목적지와 경로가 그대로 보인다",
			frame: ipv4Frame("10.0.0.5", "93.184.216.34", tcpSegment(51000, 80, nil)),
			want:  true,
		},
		{
			name:  "IPv4 UDP 123 은 거른다",
			frame: ipv4Frame("10.0.0.5", "17.253.4.125", udpSegment(51000, 123, nil)),
			want:  false,
		},
		{
			name:  "IPv6 DNS 질의는 통과한다",
			frame: ipv6Frame("fd00::5", "2606:4700:4700::1111", udpSegment(51000, 53, dns)),
			want:  true,
		},
		{
			name:  "IPv6 DNS 응답도 통과한다",
			frame: ipv6Frame("2606:4700:4700::1111", "fd00::5", udpSegment(53, 51000, dns)),
			want:  true,
		},
		{
			name:  "IPv6 TCP 443 나가는 패킷은 통과한다",
			frame: ipv6Frame("fd00::5", "2606:2800:220:1::", tcpSegment(51000, 443, tls)),
			want:  true,
		},
		{
			name:  "IPv6 TCP 443 들어오는 패킷은 거른다",
			frame: ipv6Frame("2606:2800:220:1::", "fd00::5", tcpSegment(443, 51000, tls)),
			want:  false,
		},
		{
			name:  "IPv6 TCP 80 도 통과한다",
			frame: ipv6Frame("fd00::5", "2606:2800:220:1::", tcpSegment(51000, 80, nil)),
			want:  true,
		},
		{
			name:  "IPv4 옵션이 붙어도 포트를 제대로 찾는다",
			frame: ipv4FrameOpts("10.0.0.5", "1.1.1.1", udpSegment(51000, 53, dns), 0, 2),
			want:  true,
		},
		{
			name:  "첫 조각이 아닌 IPv4 프래그먼트는 거른다. 전송 계층 헤더가 없다",
			frame: ipv4FrameOpts("10.0.0.5", "1.1.1.1", udpSegment(51000, 53, dns), 185, 0),
			want:  false,
		},
		{
			name:  "IP 가 아닌 프레임은 거른다",
			frame: ethFrame(0x0806, make([]byte, 28)), // ARP
			want:  false,
		},
		{
			name:  "잘린 프레임은 거른다",
			frame: ipv4Frame("10.0.0.5", "1.1.1.1", udpSegment(51000, 53, dns))[:20],
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, err := vm.Run(tt.frame)
			if err != nil {
				t.Fatalf("vm.Run: %v", err)
			}
			if got := n > 0; got != tt.want {
				t.Fatalf("통과 여부 = %v, 원하는 값 %v (반환 %d 바이트)", got, tt.want, n)
			}
		})
	}
}

func TestCaptureFilterSnapLen(t *testing.T) {
	vm := captureVM(t)

	// 통과한 패킷은 스냅 길이만큼 받아 와야 한다. 여기가 작으면 ClientHello 가 잘려 SNI 를 잃는다.
	n, err := vm.Run(ipv4Frame("10.0.0.5", "93.184.216.34", tcpSegment(51000, 443, nil)))
	if err != nil {
		t.Fatalf("vm.Run: %v", err)
	}
	if n != CaptureSnapLen {
		t.Fatalf("스냅 길이 = %d, 원하는 값 %d", n, CaptureSnapLen)
	}
}

// TestAsmRejectsUnknownLabel 은 라벨 해석 실패가 조용히 넘어가지 않는지 본다.
// 여기서 오류가 안 나면 목적지 없는 점프가 0 칸 점프로 조립돼 필터가 엉뚱하게 동작한다.
func TestAsmRejectsUnknownLabel(t *testing.T) {
	a := newAsm()
	a.jump("어디에도-없음")
	a.emit(bpf.RetConstant{Val: 0})

	if _, err := a.assemble(); err == nil {
		t.Fatal("없는 라벨인데 오류가 안 났다")
	}
}

// 실제 캡처 대신 손으로 만든 프레임을 쓰는 이유는 개발 기기에서 root 없이, 네트워크 상태와
// 무관하게 같은 판정을 반복할 수 있기 때문이다.

// ethFrame 은 이더넷 헤더를 붙인다.
func ethFrame(etherType uint16, payload []byte) []byte {
	frame := make([]byte, etherHeaderLen)
	copy(frame[0:6], []byte{0x02, 0, 0, 0, 0, 1})  // 목적지 MAC
	copy(frame[6:12], []byte{0x02, 0, 0, 0, 0, 2}) // 출발지 MAC
	binary.BigEndian.PutUint16(frame[12:14], etherType)
	return append(frame, payload...)
}

// segment 는 전송 계층 세그먼트 하나다.
// 프로토콜 번호를 바이트열에서 추측하지 않고 같이 들고 다니는 이유는, 페이로드 바이트가
// 우연히 TCP 헤더처럼 생기면 추측이 틀리고 그때 테스트가 조용히 엉뚱한 것을 검증하기 때문이다.
type segment struct {
	proto byte
	bytes []byte
}

// ipv4Frame 은 옵션도 프래그먼트도 없는 평범한 IPv4 프레임을 만든다.
func ipv4Frame(src, dst string, seg segment) []byte {
	return ipv4FrameOpts(src, dst, seg, 0, 0)
}

// ipv4FrameOpts 는 IPv4 프레임을 만든다.
// fragOff 는 8바이트 단위 프래그먼트 오프셋이고, optWords 는 헤더 뒤에 붙일 옵션 워드 수다.
func ipv4FrameOpts(src, dst string, seg segment, fragOff, optWords int) []byte {
	ihl := 5 + optWords
	hdr := make([]byte, ihl*4)
	hdr[0] = 4<<4 | byte(ihl)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(hdr)+len(seg.bytes)))
	binary.BigEndian.PutUint16(hdr[6:8], uint16(fragOff))
	hdr[8] = 64 // TTL
	hdr[9] = seg.proto
	copy(hdr[12:16], net.ParseIP(src).To4())
	copy(hdr[16:20], net.ParseIP(dst).To4())
	// 체크섬은 비워 둔다. BPF 필터도 packet.Parse 도 검증하지 않는다.
	return ethFrame(etherTypeIPv4, append(hdr, seg.bytes...))
}

// ipv6Frame 은 확장 헤더 없는 IPv6 프레임을 만든다.
func ipv6Frame(src, dst string, seg segment) []byte {
	hdr := make([]byte, ipv6HeaderLen)
	hdr[0] = 6 << 4
	binary.BigEndian.PutUint16(hdr[4:6], uint16(len(seg.bytes)))
	hdr[6] = seg.proto
	hdr[7] = 64 // hop limit
	copy(hdr[8:24], net.ParseIP(src).To16())
	copy(hdr[24:40], net.ParseIP(dst).To16())
	return ethFrame(etherTypeIPv6, append(hdr, seg.bytes...))
}

// udpSegment 는 UDP 헤더를 붙인다.
func udpSegment(srcPort, dstPort int, payload []byte) segment {
	hdr := make([]byte, 8)
	binary.BigEndian.PutUint16(hdr[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(hdr[2:4], uint16(dstPort))
	binary.BigEndian.PutUint16(hdr[4:6], uint16(8+len(payload)))
	return segment{proto: ipProtoUDP, bytes: append(hdr, payload...)}
}

// tcpSegment 는 옵션 없는 TCP 헤더를 붙인다.
func tcpSegment(srcPort, dstPort int, payload []byte) segment {
	hdr := make([]byte, 20)
	binary.BigEndian.PutUint16(hdr[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(hdr[2:4], uint16(dstPort))
	hdr[12] = 5 << 4 // 데이터 오프셋 5워드
	hdr[13] = 0x18   // PSH|ACK
	return segment{proto: ipProtoTCP, bytes: append(hdr, payload...)}
}

// HTTP 평문도 잡아야 한다. TLS 만 보면 암호화되지 않은 통신을 통째로 놓친다.
//
// 나가는 쪽(목적지 80)과 들어오는 쪽(출발지 80)을 둘 다 받는다. TLS 와 다른 점인데,
// 응답의 상태 코드가 조사에 쓸모가 있어서다. TLS 는 서버가 보내는 것이 인증서뿐이고
// 그건 TLS 1.3 에서 암호화돼 어차피 못 읽는다.
func TestCaptureFilterAcceptsHTTP(t *testing.T) {
	vm := captureVM(t)

	cases := map[string]struct {
		frame []byte
		want  bool
	}{
		"HTTP 요청 (목적지 80)": {ipv4Frame("10.0.0.2", "93.184.216.34", tcpSegment(51000, 80, nil)), true},
		"HTTP 응답 (출발지 80)": {ipv4Frame("93.184.216.34", "10.0.0.2", tcpSegment(80, 51000, nil)), true},
		"IPv6 요청":          {ipv6Frame("2001:db8::1", "2001:db8::2", tcpSegment(51000, 80, nil)), true},
		"IPv6 응답":          {ipv6Frame("2001:db8::2", "2001:db8::1", tcpSegment(80, 51000, nil)), true},
		// 무관한 포트는 그대로 걸러야 한다. 80 을 열었다고 필터가 헐거워지면 안 된다.
		"HTTP 대체 포트 8080": {ipv4Frame("10.0.0.2", "93.184.216.34", tcpSegment(51000, 8080, nil)), false},
		"SSH":             {ipv4Frame("10.0.0.2", "93.184.216.34", tcpSegment(51000, 22, nil)), false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			n, err := vm.Run(tc.frame)
			if err != nil {
				t.Fatalf("VM: %v", err)
			}
			if got := n > 0; got != tc.want {
				t.Errorf("통과 = %v, want %v", got, tc.want)
			}
		})
	}
}
