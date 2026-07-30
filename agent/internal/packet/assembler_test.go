package packet

import (
	"crypto/tls"
	"testing"
	"time"
)

// ClientHello 가 두 세그먼트로 쪼개지는 것은 예외가 아니라 요즘 기본값이다.
// Chrome 과 Firefox 가 양자내성 키교환(X25519MLKEM768)을 기본으로 보내면서 ClientHello 가
// 1700~2100 바이트가 됐고 MTU 1500 을 넘는다. 이 조립기가 없으면 그 SNI 를 전부 놓친다.

var asmFlow = Flow{Protocol: "tcp", SrcIP: "10.0.0.2", SrcPort: 51000, DstIP: "93.184.216.34", DstPort: 443}

func asmNow() time.Time { return time.Unix(1785400000, 0) }

// bigClientHello 는 MTU 를 넘는 ClientHello 를 만든다.
//
// 따로 부풀릴 필요가 없다. Go 의 crypto/tls 가 기본으로 내는 ClientHello 가 이미 1505 바이트다.
// 양자내성 키교환(X25519MLKEM768)의 키가 커서 그렇고, Chrome 과 Firefox 도 마찬가지다.
// 즉 이 테스트가 다루는 상황이 예외가 아니라 요즘의 기본값이다.
func bigClientHello(t *testing.T, sni string) []byte {
	t.Helper()
	full := clientHello(t, &tls.Config{ServerName: sni})
	if len(full) <= 1500 {
		t.Fatalf("ClientHello 가 %d 바이트다. MTU 를 넘겨야 이 테스트가 의미 있다", len(full))
	}
	return full
}

func TestAssemblerJoinsSplitClientHello(t *testing.T) {
	a := NewAssembler()
	full := bigClientHello(t, "split.example.com")
	first, second := full[:1400], full[1400:]

	// 첫 세그먼트만으로는 아직 모자라다.
	if _, ok := a.Push(asmFlow, first, asmNow()); ok {
		t.Fatal("첫 세그먼트만으로 완성됐다고 한다")
	}
	got, ok := a.Push(asmFlow, second, asmNow())
	if !ok {
		t.Fatal("두 세그먼트를 다 넣었는데 완성되지 않았다")
	}
	if got.SNI != "split.example.com" {
		t.Errorf("SNI = %q", got.SNI)
	}
}

func TestAssemblerHandlesSinglePacketHello(t *testing.T) {
	// 작은 ClientHello 는 한 번에 끝나야 한다. 조립기가 오히려 방해하면 안 된다.
	a := NewAssembler()
	got, ok := a.Push(asmFlow, clientHello(t, &tls.Config{ServerName: "small.example.com"}), asmNow())
	if !ok {
		t.Fatal("한 패킷짜리가 완성되지 않았다")
	}
	if got.SNI != "small.example.com" {
		t.Errorf("SNI = %q", got.SNI)
	}
}

func TestAssemblerKeepsFlowsApart(t *testing.T) {
	// 두 연결의 세그먼트가 섞이면 엉뚱한 도메인이 나온다.
	a := NewAssembler()
	other := asmFlow
	other.SrcPort = 51001

	one := bigClientHello(t, "one.example.com")
	two := bigClientHello(t, "two.example.com")

	a.Push(asmFlow, one[:1400], asmNow())
	a.Push(other, two[:1400], asmNow())

	got, ok := a.Push(other, two[1400:], asmNow())
	if !ok || got.SNI != "two.example.com" {
		t.Fatalf("두 번째 흐름 = %+v ok=%v", got, ok)
	}
	got, ok = a.Push(asmFlow, one[1400:], asmNow())
	if !ok || got.SNI != "one.example.com" {
		t.Fatalf("첫 번째 흐름 = %+v ok=%v", got, ok)
	}
}

func TestAssemblerDropsFlowAfterCompletion(t *testing.T) {
	// 완성한 흐름을 계속 들고 있으면 재전송 때 같은 SNI 를 또 낸다.
	a := NewAssembler()
	hello := clientHello(t, &tls.Config{ServerName: "once.example.com"})

	if _, ok := a.Push(asmFlow, hello, asmNow()); !ok {
		t.Fatal("첫 시도가 실패했다")
	}
	if _, ok := a.Push(asmFlow, hello, asmNow()); ok {
		t.Error("같은 흐름에서 두 번째로 완성됐다고 한다")
	}
	if a.Len() != 0 {
		t.Errorf("완성 후에도 흐름이 %d 개 남아있다", a.Len())
	}
}

func TestAssemblerDropsNonTLSFlowImmediately(t *testing.T) {
	// 443 이 아닌 것이 섞여 들어와도 버퍼를 먹으면 안 된다.
	a := NewAssembler()
	if _, ok := a.Push(asmFlow, []byte("GET / HTTP/1.1\r\n\r\n"), asmNow()); ok {
		t.Error("TLS 가 아닌데 완성됐다고 한다")
	}
	if a.Len() != 0 {
		t.Errorf("TLS 가 아닌 흐름을 %d 개 들고 있다", a.Len())
	}
}

func TestAssemblerEnforcesByteLimit(t *testing.T) {
	// 신뢰할 수 없는 입력이다. 상한이 없으면 메모리 고갈 공격의 표적이 된다.
	a := NewAssembler()
	// 레코드 헤더는 TLS 로 보이게 두되 끝나지 않는 조각을 계속 넣는다.
	head := []byte{recordHandshake, 3, 1, 0xff, 0xff}
	a.Push(asmFlow, head, asmNow())
	for i := 0; i < 20; i++ {
		a.Push(asmFlow, make([]byte, 1024), asmNow())
	}
	if a.Len() != 0 {
		t.Errorf("상한을 넘겼는데 흐름이 %d 개 남아있다", a.Len())
	}
}

func TestAssemblerExpiresStaleFlows(t *testing.T) {
	// 완성되지 않은 흐름이 영원히 남으면 맵이 계속 커진다.
	a := NewAssembler()
	full := bigClientHello(t, "stale.example.com")
	a.Push(asmFlow, full[:1400], asmNow())
	if a.Len() != 1 {
		t.Fatalf("흐름이 %d 개다", a.Len())
	}

	later := asmNow().Add(assemblerTTL + time.Second)
	other := asmFlow
	other.SrcPort = 52000
	a.Push(other, []byte{recordHandshake, 3, 1, 0xff, 0xff}, later)

	// 만료된 흐름은 사라지고 방금 넣은 것만 남아야 한다.
	if a.Len() != 1 {
		t.Errorf("만료 정리 후 흐름 %d 개", a.Len())
	}
	if _, ok := a.Push(asmFlow, full[1400:], later); ok {
		t.Error("만료된 흐름이 이어져 완성됐다")
	}
}

func TestAssemblerCapsTrackedFlows(t *testing.T) {
	a := NewAssembler()
	head := []byte{recordHandshake, 3, 1, 0xff, 0xff}
	for i := 0; i < assemblerMaxFlows+50; i++ {
		f := asmFlow
		f.SrcPort = 40000 + i
		a.Push(f, head, asmNow())
	}
	if a.Len() > assemblerMaxFlows {
		t.Errorf("추적 흐름이 %d 개다. 상한 %d", a.Len(), assemblerMaxFlows)
	}
}

func TestAssemblerSurvivesGarbage(t *testing.T) {
	// 조각난 입력을 이어 붙이는 코드라 상태가 꼬이기 쉽다. panic 하면 센서가 죽는다.
	a := NewAssembler()
	inputs := [][]byte{
		nil,
		{},
		{recordHandshake},
		{recordHandshake, 3, 1},
		{recordHandshake, 3, 1, 0, 0},
		{recordHandshake, 3, 1, 0xff, 0xff, 1},
		{recordHandshake, 3, 1, 0, 4, 1, 0xff, 0xff, 0xff},
	}
	for _, in := range inputs {
		f := asmFlow
		f.SrcPort = 30000 + len(in)
		a.Push(f, in, asmNow())
	}
}
