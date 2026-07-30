package packet

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// ClientHello 는 TLS 핸드셰이크 첫 메시지에서 뽑은 값이다.
//
// 인증서는 담지 않는다. TLS 1.3 은 ServerHello 직후 핸드셰이크 키를 도출해서 Certificate
// 메시지부터 암호화하므로 평문 캡처로는 볼 방법 자체가 없다. TLS 1.2 에서만 평문인데 체인이
// 3~5KB 라 완전한 재조립이 필요하고, 그 비용을 들여도 점점 줄어드는 소수만 얻는다.
// 반면 ClientHello 는 어느 버전에서도 평문이라 여기서 뽑는 값이 실제로 남는 값이다.
type ClientHello struct {
	SNI     string
	Version string   // 협상 시도 버전
	ALPN    []string // 제안한 응용 프로토콜. "h2", "http/1.1" 등
}

const (
	recordHandshake = 22 // TLS 레코드 content type
	msgClientHello  = 1  // handshake type

	extServerName        = 0
	extALPN              = 16
	extSupportedVersions = 43

	sniHostName = 0 // server_name_list 의 name_type
)

// ParseClientHello 는 TCP 페이로드에서 SNI, 협상 시도 버전, ALPN 을 꺼낸다.
//
// 입력은 ClientHello 레코드가 통째로 담긴 바이트여야 한다. **요즘 ClientHello 는 한 패킷에
// 안 들어온다.** 양자내성 키교환이 기본이 되면서 1700~2100 바이트가 되어 MTU 를 넘기 때문에,
// 캡처한 세그먼트를 그대로 넘기면 대부분 false 가 난다. 세그먼트를 모으는 일은 Assembler 가
// 하고 이 함수는 완성된 바이트만 받는다.
//
// SNI 가 없어도 true 를 준다. 버전과 ALPN 만으로도 조사에 쓸모가 있고, 도메인이 필요한
// 호출자는 SNI 가 비었는지 직접 보면 된다. 여기서 false 를 주면 "TLS 였다" 는 사실까지 잃는다.
func ParseClientHello(payload []byte) (ClientHello, bool) {
	body, ok := handshakeBody(payload, msgClientHello)
	if !ok {
		return ClientHello{}, false
	}

	r := reader{b: body}
	legacy, ok := r.uint16()
	if !ok {
		return ClientHello{}, false
	}
	if _, ok := r.take(32); !ok { // random
		return ClientHello{}, false
	}
	if _, ok := r.vector8(); !ok { // legacy_session_id
		return ClientHello{}, false
	}
	if _, ok := r.vector16(); !ok { // cipher_suites
		return ClientHello{}, false
	}
	if _, ok := r.vector8(); !ok { // legacy_compression_methods
		return ClientHello{}, false
	}

	hello := ClientHello{Version: versionName(legacy)}
	exts, ok := r.vector16()
	if !ok {
		// 확장이 아예 없는 ClientHello 는 유효하다(TLS 1.2 이하). 버전만 들고 나간다.
		return hello, r.empty()
	}

	e := reader{b: exts}
	for !e.empty() {
		extType, ok := e.uint16()
		if !ok {
			return ClientHello{}, false
		}
		data, ok := e.vector16()
		if !ok {
			return ClientHello{}, false
		}
		switch extType {
		case extServerName:
			name, ok := parseSNI(data)
			if !ok {
				return ClientHello{}, false
			}
			hello.SNI = name
		case extALPN:
			protos, ok := parseALPN(data)
			if !ok {
				return ClientHello{}, false
			}
			hello.ALPN = protos
		case extSupportedVersions:
			// TLS 1.3 은 레코드 호환을 위해 앞의 버전 필드를 1.2 로 고정하고 진짜 시도 버전을
			// 여기에 넣는다. 이걸 안 보면 모든 최신 클라이언트가 TLS 1.2 로 기록된다.
			if v, ok := highestVersion(data); ok {
				hello.Version = versionName(v)
			}
		}
	}
	return hello, true
}

// parseSNI 는 server_name 확장에서 host_name 을 꺼낸다.
func parseSNI(data []byte) (string, bool) {
	list, ok := (&reader{b: data}).vector16()
	if !ok {
		return "", false
	}
	r := reader{b: list}
	for !r.empty() {
		nameType, ok := r.uint8()
		if !ok {
			return "", false
		}
		name, ok := r.vector16()
		if !ok {
			return "", false
		}
		if nameType == sniHostName {
			// SNI 도 소문자로 낮춘다. DNS 이름과 같은 값이라 같은 규칙으로 정규화해야
			// 대시보드에서 dns 이벤트와 l7 이벤트가 한 도메인으로 묶인다.
			return strings.ToLower(string(name)), true
		}
	}
	return "", true
}

// parseALPN 은 클라이언트가 제안한 응용 프로토콜 목록을 꺼낸다.
//
// 조사에서 쓸모가 있는 이유는 포트만으로는 알 수 없는 것을 알려주기 때문이다. 443 으로
// 나가는 트래픽이 브라우저의 h2 인지 뭔가가 직접 연 TLS 소켓인지가 여기서 갈린다.
func parseALPN(data []byte) ([]string, bool) {
	list, ok := (&reader{b: data}).vector16()
	if !ok {
		return nil, false
	}
	var protos []string
	r := reader{b: list}
	for !r.empty() {
		name, ok := r.vector8()
		if !ok {
			return nil, false
		}
		if len(name) == 0 {
			continue // 규격 위반이지만 버릴 이유까지는 아니다
		}
		protos = append(protos, string(name))
	}
	return protos, true
}

// highestVersion 은 supported_versions 목록에서 가장 높은 버전을 고른다.
func highestVersion(data []byte) (int, bool) {
	list, ok := (&reader{b: data}).vector8()
	if !ok {
		return 0, false
	}
	best := 0
	r := reader{b: list}
	for !r.empty() {
		v, ok := r.uint16()
		if !ok {
			return 0, false
		}
		// GREASE 값은 구현이 모르는 값을 잘 무시하는지 보려고 끼워 넣는 가짜다. 버전이 아니다.
		if v&0x0f0f == 0x0a0a {
			continue
		}
		if v > best {
			best = v
		}
	}
	return best, best != 0
}

// handshakeBody 는 페이로드에 담긴 TLS 레코드를 훑어 원하는 핸드셰이크 메시지 본문을 찾는다.
//
// 한 레코드에 여러 핸드셰이크 메시지가 들어가기도 하고 한 패킷에 여러 레코드가 들어가기도 해서
// 양쪽 모두 순회한다.
//
// 레코드나 메시지가 이 바이트 안에서 끝나지 않으면 false 다. 여기서 뒤를 기다리지 않는 이유는
// 기다릴 상태가 없기 때문이다. 그 일은 Assembler 가 흐름별로 한다.
func handshakeBody(payload []byte, want byte) ([]byte, bool) {
	for len(payload) >= 5 {
		if payload[0] != recordHandshake {
			return nil, false
		}
		recLen := int(binary.BigEndian.Uint16(payload[3:5]))
		if recLen == 0 || 5+recLen > len(payload) {
			return nil, false
		}
		frag := payload[5 : 5+recLen]
		for len(frag) >= 4 {
			msgLen, _ := uint24(frag[1:])
			if 4+msgLen > len(frag) {
				return nil, false
			}
			if frag[0] == want {
				return frag[4 : 4+msgLen], true
			}
			frag = frag[4+msgLen:]
		}
		payload = payload[5+recLen:]
	}
	return nil, false
}

func versionName(v int) string {
	switch v {
	case 0x0300:
		return "SSL 3.0"
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	}
	return fmt.Sprintf("0x%04x", v)
}

// reader 는 경계 검사를 한곳에 모은 바이트 커서다.
//
// TLS 는 길이 필드가 겹겹이 쌓인 구조라 손으로 인덱싱하면 검사를 한 군데 빠뜨리기 쉽고,
// 그 한 군데가 조작된 패킷에서 panic 이 된다. 읽기는 전부 이 타입을 거친다.
// x/crypto/cryptobyte 와 같은 패턴이고, 여기서 필요한 것은 그중 여섯 가지뿐이다.
type reader struct{ b []byte }

func (r *reader) empty() bool { return len(r.b) == 0 }

func (r *reader) take(n int) ([]byte, bool) {
	if n < 0 || n > len(r.b) {
		return nil, false
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out, true
}

func (r *reader) uint8() (int, bool) {
	v, ok := r.take(1)
	if !ok {
		return 0, false
	}
	return int(v[0]), true
}

func (r *reader) uint16() (int, bool) {
	v, ok := r.take(2)
	if !ok {
		return 0, false
	}
	return int(binary.BigEndian.Uint16(v)), true
}

// vector8 은 1바이트 길이가 앞에 붙은 가변 길이 필드를 읽는다. vector16 도 같고 길이만 2바이트다.
func (r *reader) vector8() ([]byte, bool) {
	n, ok := r.uint8()
	if !ok {
		return nil, false
	}
	return r.take(n)
}

func (r *reader) vector16() ([]byte, bool) {
	n, ok := r.uint16()
	if !ok {
		return nil, false
	}
	return r.take(n)
}

func uint24(b []byte) (int, bool) {
	if len(b) < 3 {
		return 0, false
	}
	return int(b[0])<<16 | int(b[1])<<8 | int(b[2]), true
}
