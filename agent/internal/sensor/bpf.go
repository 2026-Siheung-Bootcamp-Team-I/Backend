package sensor

import (
	"fmt"

	"golang.org/x/net/bpf"
)

// CaptureSnapLen 은 패킷 하나당 커널에서 복사해 올 최대 바이트다.
// 줄이면 ClientHello 가 잘려 SNI 확장이 통째로 날아간다.
const CaptureSnapLen = 2048

// 필터가 쓰는 상수. 이더넷 프레임 기준의 고정 오프셋이다.
const (
	etherTypeOffset = 12
	etherHeaderLen  = 14

	etherTypeIPv4 = 0x0800
	etherTypeIPv6 = 0x86dd

	ipProtoTCP = 6
	ipProtoUDP = 17

	// IPv6 헤더는 40바이트 고정이라 전송 계층 위치를 바로 계산할 수 있다.
	ipv6HeaderLen = 40

	portDNS   = 53
	portHTTPS = 443
	// portHTTP 는 평문 HTTP 다.
	portHTTP = 80
)

// CaptureFilter 는 커널에 걸 BPF 프로그램을 만든다. DNS 와 TLS/HTTP 핸드셰이크만 통과시킨다.
// 필터를 안 걸면 링크를 지나는 모든 패킷이 유저 공간으로 복사돼 CPU 를 통째로 먹는다.
func CaptureFilter() ([]bpf.RawInstruction, error) {
	a := newAsm()

	// 이더넷 타입으로 IPv4 와 IPv6 를 가른다. macOS BPF 는 이더넷 헤더까지 준다.
	a.emit(bpf.LoadAbsolute{Off: etherTypeOffset, Size: 2})
	a.jeq(etherTypeIPv4, "ipv4")
	a.jeq(etherTypeIPv6, "ipv6")
	a.jump("reject")

	a.mark("ipv4")
	// 이 검사를 빼면 프래그먼트의 페이로드 바이트를 포트로 착각해 엉뚱한 패킷이 통과한다.
	a.emit(bpf.LoadAbsolute{Off: etherHeaderLen + 6, Size: 2})
	a.jset(0x1fff, "reject")
	a.emit(bpf.LoadAbsolute{Off: etherHeaderLen + 9, Size: 1}) // protocol
	// IHL 만큼 X 를 밀어 둔다. 20 으로 고정하면 옵션이 붙은 헤더에서 포트 위치가 어긋난다.
	a.emit(bpf.LoadMemShift{Off: etherHeaderLen})
	a.jeq(ipProtoUDP, "v4udp")
	a.jeq(ipProtoTCP, "v4tcp")
	a.jump("reject")

	// 전송 계층은 이더넷 헤더 다음 X 바이트 뒤에서 시작한다. LoadIndirect 가 X 를 더해 준다.
	a.mark("v4udp")
	a.emit(bpf.LoadIndirect{Off: etherHeaderLen + 0, Size: 2}) // src port
	a.jeq(portDNS, "accept")
	a.emit(bpf.LoadIndirect{Off: etherHeaderLen + 2, Size: 2}) // dst port
	a.jeq(portDNS, "accept")
	a.jump("reject")

	a.mark("v4tcp")
	a.emit(bpf.LoadIndirect{Off: etherHeaderLen + 2, Size: 2}) // dst port
	a.jeq(portHTTPS, "accept")
	a.jeq(portHTTP, "accept")
	// 출발지 80 도 받는다. 빼면 HTTP 응답이 안 잡혀 상태 코드를 못 본다.
	a.emit(bpf.LoadIndirect{Off: etherHeaderLen + 0, Size: 2}) // src port
	a.jeq(portHTTP, "accept")
	a.jump("reject")

	a.mark("ipv6")
	a.emit(bpf.LoadAbsolute{Off: etherHeaderLen + 6, Size: 1}) // next header
	a.jeq(ipProtoUDP, "v6udp")
	a.jeq(ipProtoTCP, "v6tcp")
	a.jump("reject")

	a.mark("v6udp")
	a.emit(bpf.LoadAbsolute{Off: etherHeaderLen + ipv6HeaderLen + 0, Size: 2})
	a.jeq(portDNS, "accept")
	a.emit(bpf.LoadAbsolute{Off: etherHeaderLen + ipv6HeaderLen + 2, Size: 2})
	a.jeq(portDNS, "accept")
	a.jump("reject")

	a.mark("v6tcp")
	a.emit(bpf.LoadAbsolute{Off: etherHeaderLen + ipv6HeaderLen + 2, Size: 2})
	a.jeq(portHTTPS, "accept")
	a.jeq(portHTTP, "accept")
	a.emit(bpf.LoadAbsolute{Off: etherHeaderLen + ipv6HeaderLen + 0, Size: 2})
	a.jeq(portHTTP, "accept")
	a.jump("reject")

	// 반환값은 커널이 넘겨줄 바이트 수다. 0 이면 그 패킷은 버려진다.
	a.mark("accept")
	a.emit(bpf.RetConstant{Val: CaptureSnapLen})
	a.mark("reject")
	a.emit(bpf.RetConstant{Val: 0})

	return a.assemble()
}

// asm 은 점프 목적지를 이름으로 쓰게 해 주는 조립기다.
// 거리를 손으로 세면 명령 하나만 끼워 넣어도 오류 없이 필터만 조용히 잘못 동작한다.
type asm struct {
	insts []bpf.Instruction
	marks map[string]int
	fixes []asmFix
}

// asmFix 는 아직 목적지를 모르는 점프 하나다.
type asmFix struct {
	at    int    // insts 안의 위치
	label string // 가야 할 곳
}

func newAsm() *asm {
	return &asm{marks: map[string]int{}}
}

func (a *asm) emit(inst bpf.Instruction) {
	a.insts = append(a.insts, inst)
}

// mark 는 지금 위치에 이름을 붙인다.
func (a *asm) mark(label string) {
	a.marks[label] = len(a.insts)
}

// jeq 는 A 가 val 이면 label 로 뛰고 아니면 다음 명령으로 흘린다.
func (a *asm) jeq(val uint32, label string) {
	a.jumpIf(bpf.JumpEqual, val, label)
}

// jset 은 A 에 val 비트가 하나라도 서 있으면 label 로 뛴다.
func (a *asm) jset(val uint32, label string) {
	a.jumpIf(bpf.JumpBitsSet, val, label)
}

func (a *asm) jumpIf(cond bpf.JumpTest, val uint32, label string) {
	a.fixes = append(a.fixes, asmFix{at: len(a.insts), label: label})
	a.emit(bpf.JumpIf{Cond: cond, Val: val})
}

// jump 는 무조건 label 로 뛴다.
func (a *asm) jump(label string) {
	a.fixes = append(a.fixes, asmFix{at: len(a.insts), label: label})
	a.emit(bpf.Jump{})
}

// assemble 은 라벨을 실제 거리로 바꾸고 바이트코드를 만든다.
func (a *asm) assemble() ([]bpf.RawInstruction, error) {
	for _, f := range a.fixes {
		target, ok := a.marks[f.label]
		if !ok {
			return nil, fmt.Errorf("bpf: 라벨 %q 가 없다", f.label)
		}
		// 점프는 다음 명령을 기준으로 센다.
		skip := target - f.at - 1
		if skip < 0 {
			return nil, fmt.Errorf("bpf: 라벨 %q 로 되돌아가는 점프는 BPF 가 허용하지 않는다", f.label)
		}
		switch inst := a.insts[f.at].(type) {
		case bpf.JumpIf:
			// 조건 점프의 거리는 1바이트다. 넘으면 조립기가 잘못된 거리를 만들어 낸다.
			if skip > 255 {
				return nil, fmt.Errorf("bpf: 라벨 %q 까지 거리가 %d 로 너무 멀다", f.label, skip)
			}
			inst.SkipTrue = uint8(skip)
			a.insts[f.at] = inst
		case bpf.Jump:
			inst.Skip = uint32(skip)
			a.insts[f.at] = inst
		default:
			return nil, fmt.Errorf("bpf: %d 번 명령은 점프가 아니다", f.at)
		}
	}
	return bpf.Assemble(a.insts)
}
