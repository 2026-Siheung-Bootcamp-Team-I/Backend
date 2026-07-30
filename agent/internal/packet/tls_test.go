package packet

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// deadConn 은 crypto/tls 가 쓴 바이트만 받아 두는 가짜 연결이다.
//
// ClientHello 픽스처를 진짜 TLS 구현으로 만들려는 것이다. 손으로 적은 확장 목록은 실제
// 클라이언트가 보내는 것과 어긋나기 쉽고, 그러면 테스트를 통과해도 현장에서 SNI 를 놓친다.
// 읽기는 곧바로 EOF 라 핸드셰이크는 ClientHello 를 쓴 직후 실패하는데, 우리에게 필요한 것은
// 그 앞에서 이미 버퍼에 담긴 바이트뿐이다.
type deadConn struct{ w *bytes.Buffer }

func (c deadConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c deadConn) Write(p []byte) (int, error)      { return c.w.Write(p) }
func (c deadConn) Close() error                     { return nil }
func (c deadConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c deadConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c deadConn) SetDeadline(time.Time) error      { return nil }
func (c deadConn) SetReadDeadline(time.Time) error  { return nil }
func (c deadConn) SetWriteDeadline(time.Time) error { return nil }

func clientHello(t testing.TB, cfg *tls.Config) []byte {
	t.Helper()
	var buf bytes.Buffer
	_ = tls.Client(deadConn{w: &buf}, cfg).Handshake() // EOF 로 실패하는 것이 정상이다
	if buf.Len() == 0 {
		t.Fatal("ClientHello 가 나오지 않았다")
	}
	return buf.Bytes()
}

func TestParseClientHelloExtractsSNI(t *testing.T) {
	hello, ok := ParseClientHello(clientHello(t, &tls.Config{ServerName: "example.com"}))
	if !ok {
		t.Fatal("ParseClientHello 가 false 를 돌려줬다")
	}
	if hello.SNI != "example.com" {
		t.Errorf("SNI = %q, want example.com", hello.SNI)
	}
}

// SNI 는 DNS 이름과 같은 값이라 같은 규칙으로 낮춰야 dns 이벤트와 한 도메인으로 묶인다.
func TestParseClientHelloNormalizesSNI(t *testing.T) {
	hello, ok := ParseClientHello(clientHello(t, &tls.Config{ServerName: "WWW.Example.COM"}))
	if !ok {
		t.Fatal("ParseClientHello 가 false 를 돌려줬다")
	}
	if hello.SNI != "www.example.com" {
		t.Errorf("SNI = %q, want www.example.com", hello.SNI)
	}
}

// SNI 가 없어도 "TLS 였다" 는 사실은 남긴다. 도메인이 필요한 호출자가 직접 판단한다.
func TestParseClientHelloWithoutSNI(t *testing.T) {
	raw := clientHello(t, &tls.Config{InsecureSkipVerify: true})

	hello, ok := ParseClientHello(raw)
	if !ok {
		t.Fatal("SNI 가 없다고 false 를 주면 버전 정보까지 잃는다")
	}
	if hello.SNI != "" {
		t.Errorf("SNI = %q, want 빈 문자열", hello.SNI)
	}
	if hello.Version == "" {
		t.Error("버전이 비었다")
	}
}

// TLS 1.3 은 앞의 버전 필드를 1.2 로 고정하고 진짜 시도 버전은 supported_versions 에 넣는다.
// 앞 필드만 읽으면 최신 클라이언트가 전부 TLS 1.2 로 기록된다.
func TestParseClientHelloVersion(t *testing.T) {
	cases := map[string]struct {
		cfg  *tls.Config
		want string
	}{
		"기본(1.3 시도)": {&tls.Config{ServerName: "a.example.com"}, "TLS 1.3"},
		"1.2 상한":     {&tls.Config{ServerName: "b.example.com", MaxVersion: tls.VersionTLS12}, "TLS 1.2"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			hello, ok := ParseClientHello(clientHello(t, tc.cfg))
			if !ok {
				t.Fatal("ParseClientHello 가 false 를 돌려줬다")
			}
			if hello.Version != tc.want {
				t.Errorf("Version = %q, want %q", hello.Version, tc.want)
			}
		})
	}
}

// 실제 ClientHello 에는 확장이 십여 개 붙는다. server_name 이 그중 어디에 있어도 찾아야 한다.
func TestParseClientHelloWalksManyExtensions(t *testing.T) {
	raw := clientHello(t, &tls.Config{
		ServerName:   "many.example.com",
		NextProtos:   []string{"h2", "http/1.1"},
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	})

	if n := countExtensions(t, raw); n < 5 {
		t.Fatalf("확장이 %d 개뿐이다. 여러 확장을 훑는지 검증하지 못한다", n)
	}
	hello, ok := ParseClientHello(raw)
	if !ok {
		t.Fatal("ParseClientHello 가 false 를 돌려줬다")
	}
	if hello.SNI != "many.example.com" {
		t.Errorf("SNI = %q, want many.example.com", hello.SNI)
	}
}

// countExtensions 는 픽스처가 실제로 확장을 여럿 담았는지 세어 본다. 테스트의 전제 확인용이다.
func countExtensions(t testing.TB, payload []byte) int {
	t.Helper()
	body, ok := handshakeBody(payload, msgClientHello)
	if !ok {
		t.Fatal("ClientHello 를 찾지 못했다")
	}
	r := reader{b: body}
	r.uint16()
	r.take(32)
	r.vector8()
	r.vector16()
	r.vector8()
	exts, ok := r.vector16()
	if !ok {
		return 0
	}
	e := reader{b: exts}
	n := 0
	for !e.empty() {
		if _, ok := e.uint16(); !ok {
			break
		}
		if _, ok := e.vector16(); !ok {
			break
		}
		n++
	}
	return n
}

// 한 세그먼트에 다 안 들어온 ClientHello 는 재조립하지 않고 버린다.
func TestParseClientHelloTruncated(t *testing.T) {
	raw := clientHello(t, &tls.Config{ServerName: "example.com"})

	for i := range len(raw) {
		if _, ok := ParseClientHello(raw[:i]); ok {
			t.Fatalf("%d 바이트만 왔는데 true 를 줬다", i)
		}
	}
}

func TestParseClientHelloRejectsNonHandshake(t *testing.T) {
	cases := map[string][]byte{
		"빈 입력":             {},
		"레코드 헤더 미달":        {0x16, 0x03, 0x01},
		"application data": {0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5},
		"핸드셰이크지만 다른 메시지": func() []byte {
			// ServerHello(2) 만 든 레코드. ClientHello 가 아니다.
			body := make([]byte, 10)
			return tlsRecord(handshakeMessage(2, body))
		}(),
		"DNS 질의": dnsQuery(t, "example.com.", 1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, ok := ParseClientHello(raw); ok {
				t.Error("true 를 줬다")
			}
		})
	}
}

func TestParseClientHelloFromFullFrame(t *testing.T) {
	raw := clientHello(t, &tls.Config{ServerName: "c2.example.net"})
	frame := ethernet(etherTypeIPv6, ipv6(protoTCP, "2001:db8::1", "2001:db8::2", tcp(52000, 443, nil, raw)))

	flow, payload, ok := Parse(frame, LinkEthernet)
	if !ok {
		t.Fatal("프레임을 벗기지 못했다")
	}
	if flow.DstPort != 443 {
		t.Fatalf("DstPort = %d, want 443", flow.DstPort)
	}

	hello, ok := ParseClientHello(payload)
	if !ok {
		t.Fatal("페이로드에서 ClientHello 를 읽지 못했다")
	}
	if hello.SNI != "c2.example.net" {
		t.Errorf("SNI = %q, want c2.example.net", hello.SNI)
	}
}

// --- 손으로 만든 ClientHello ---

func tlsRecord(payload []byte) []byte {
	h := []byte{recordHandshake, 0x03, 0x03, 0, 0}
	binary.BigEndian.PutUint16(h[3:5], uint16(len(payload)))
	return append(h, payload...)
}

func handshakeMessage(msgType byte, body []byte) []byte {
	h := []byte{msgType, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(h, body...)
}

//
// crypto/tls 는 이제 TLS 1.0 hello 나 이상한 확장을 만들어 주지 않는다. 그래도 캡처에는
// 낡은 클라이언트와 규격을 어긴 구현이 섞여 들어오므로 그 모양은 직접 조립해서 검증한다.

func rawClientHello(legacy uint16, exts []byte) []byte {
	body := []byte{byte(legacy >> 8), byte(legacy)}
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)                   // legacy_session_id 없음
	body = append(body, 0, 2, 0x13, 0x01)    // cipher_suites 하나
	body = append(body, 1, 0)                // compression: null 만
	if exts != nil {
		body = append(body, byte(len(exts)>>8), byte(len(exts)))
		body = append(body, exts...)
	}
	return tlsRecord(handshakeMessage(msgClientHello, body))
}

func extension(typ uint16, data []byte) []byte {
	h := []byte{byte(typ >> 8), byte(typ), byte(len(data) >> 8), byte(len(data))}
	return append(h, data...)
}

func sniEntry(nameType byte, host string) []byte {
	e := []byte{nameType, byte(len(host) >> 8), byte(len(host))}
	return append(e, []byte(host)...)
}

func sniExtension(entries ...[]byte) []byte {
	var list []byte
	for _, e := range entries {
		list = append(list, e...)
	}
	data := append([]byte{byte(len(list) >> 8), byte(len(list))}, list...)
	return extension(extServerName, data)
}

func supportedVersions(versions ...uint16) []byte {
	list := make([]byte, 0, len(versions)*2)
	for _, v := range versions {
		list = append(list, byte(v>>8), byte(v))
	}
	data := append([]byte{byte(len(list))}, list...)
	return extension(extSupportedVersions, data)
}

func TestParseClientHelloLegacyVersion(t *testing.T) {
	cases := map[uint16]string{
		0x0300: "SSL 3.0",
		0x0301: "TLS 1.0",
		0x0302: "TLS 1.1",
		0x0303: "TLS 1.2",
		0x0305: "0x0305", // 아직 없는 버전. 숫자로 남겨 값을 잃지 않는다
	}
	for legacy, want := range cases {
		hello, ok := ParseClientHello(rawClientHello(legacy, sniExtension(sniEntry(sniHostName, "old.example.com"))))
		if !ok {
			t.Fatalf("legacy %#04x 에서 false", legacy)
		}
		if hello.Version != want {
			t.Errorf("Version = %q, want %q", hello.Version, want)
		}
		if hello.SNI != "old.example.com" {
			t.Errorf("SNI = %q, want old.example.com", hello.SNI)
		}
	}
}

// 확장이 아예 없는 ClientHello 는 TLS 1.2 이하에서 유효하다. 버림이 아니라 버전만 남긴다.
func TestParseClientHelloWithoutExtensions(t *testing.T) {
	hello, ok := ParseClientHello(rawClientHello(0x0301, nil))
	if !ok {
		t.Fatal("확장이 없다고 false 를 줬다")
	}
	if hello.Version != "TLS 1.0" || hello.SNI != "" {
		t.Errorf("hello = %+v, want {SNI: \"\", Version: TLS 1.0}", hello)
	}
}

// GREASE 는 구현이 모르는 값을 잘 무시하는지 보려고 끼워 넣는 가짜다. 버전으로 읽으면 안 된다.
func TestParseClientHelloIgnoresGREASEVersions(t *testing.T) {
	t.Run("GREASE 섞임", func(t *testing.T) {
		hello, ok := ParseClientHello(rawClientHello(0x0303, supportedVersions(0x3a3a, 0x0304, 0x0303)))
		if !ok {
			t.Fatal("ParseClientHello 가 false 를 돌려줬다")
		}
		if hello.Version != "TLS 1.3" {
			t.Errorf("Version = %q, want TLS 1.3", hello.Version)
		}
	})

	t.Run("GREASE 뿐", func(t *testing.T) {
		hello, ok := ParseClientHello(rawClientHello(0x0303, supportedVersions(0x3a3a, 0x1a1a)))
		if !ok {
			t.Fatal("ParseClientHello 가 false 를 돌려줬다")
		}
		if hello.Version != "TLS 1.2" {
			t.Errorf("Version = %q, want TLS 1.2 (앞 필드로 되돌아가야 한다)", hello.Version)
		}
	})
}

// server_name 확장은 목록이라 host_name 이 아닌 항목이 앞에 올 수 있다.
func TestParseClientHelloSkipsNonHostNameEntries(t *testing.T) {
	exts := sniExtension(sniEntry(9, "ignored"), sniEntry(sniHostName, "real.example.com"))

	hello, ok := ParseClientHello(rawClientHello(0x0303, exts))
	if !ok {
		t.Fatal("ParseClientHello 가 false 를 돌려줬다")
	}
	if hello.SNI != "real.example.com" {
		t.Errorf("SNI = %q, want real.example.com", hello.SNI)
	}
}

// 확장 안쪽 길이 필드도 공격자가 정한다. 겉의 길이만 믿으면 범위를 넘는다.
func TestParseClientHelloRejectsMalformedExtensions(t *testing.T) {
	cases := map[string][]byte{
		"SNI 목록 길이 과다":  extension(extServerName, []byte{0xff, 0xff, 0x00, 0x00, 0x03, 'a', 'b', 'c'}),
		"SNI 호스트 길이 과다": extension(extServerName, []byte{0x00, 0x06, 0x00, 0xff, 0xff, 'a', 'b', 'c'}),
		"SNI 확장이 빈 경우":  extension(extServerName, nil),
		"확장 길이 과다":      {0x00, 0x00, 0xff, 0xff},
		"확장 헤더 잘림":      {0x00},
	}
	for name, exts := range cases {
		t.Run(name, func(t *testing.T) {
			if _, ok := ParseClientHello(rawClientHello(0x0303, exts)); ok {
				t.Error("길이 필드가 깨졌는데 true 를 줬다")
			}
		})
	}
}
