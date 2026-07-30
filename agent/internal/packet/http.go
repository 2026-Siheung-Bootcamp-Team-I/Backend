package packet

import (
	"bytes"
	"strings"
)

// HTTPMessage 는 평문 HTTP 에서 뽑은 메타데이터다.
//
// 본문은 담지 않는다. 평문 HTTP 는 마음만 먹으면 주고받은 내용을 통째로 읽을 수 있는데,
// 그건 이 패키지가 하기로 한 일이 아니다. "어디에 접속했나" 를 말해 주는 값만 남긴다.
//
// 요청과 응답을 한 타입으로 다룬다. 흐름의 한쪽만 보고도 쓸 값이 나오기 때문이다. 요청에서는
// 메서드와 호스트와 경로가, 응답에서는 상태 코드가 나온다. IsResponse 로 어느 쪽인지 가린다.
type HTTPMessage struct {
	IsResponse bool
	Method     string // 요청일 때
	Host       string // Host 헤더
	Path       string // 요청 경로. 질의 문자열은 뗀다
	UserAgent  string
	StatusCode int // 응답일 때
}

const (
	// httpMaxLine 은 한 줄의 최대 길이다.
	//
	// 정상 요청 라인은 길어야 수백 바이트다. 이 상한이 없으면 개행 없는 바이트 뭉치를
	// 계속 훑게 되고, 신뢰할 수 없는 입력에서 그건 그대로 CPU 를 태우는 길이다.
	httpMaxLine = 8 * 1024
	// httpMaxHeaderLines 는 훑을 헤더 줄 수다.
	// Host 와 User-Agent 는 거의 항상 앞쪽에 온다. 뒤까지 볼 이유가 없다.
	httpMaxHeaderLines = 32

	// 값마다 길이를 자른다. 헤더 값은 보내는 쪽이 정하므로 이벤트 하나가 얼마나 커질 수
	// 있는지도 보내는 쪽이 정하게 된다. 잘린 값도 조사에는 충분히 쓸모가 있다.
	httpMaxPath      = 1024
	httpMaxHost      = 256
	httpMaxUserAgent = 512
)

var (
	headerHost      = []byte("host")
	headerUserAgent = []byte("user-agent")
)

// ParseHTTP 는 TCP 페이로드에서 평문 HTTP 의 메타데이터를 꺼낸다.
//
// **재조립하지 않는다.** 첫 세그먼트에서 읽히는 것만 읽는다. 그렇게 정한 이유는 두 가지다.
// 하나는 요청 라인과 Host 가 헤더의 맨 앞이라 한 세그먼트(보통 1460 바이트)에 거의 항상
// 들어온다는 것이다. TLS 의 ClientHello 는 키교환 자료 때문에 MTU 를 넘는 것이 기본값이라
// 사정이 다르다. 다른 하나는 Assembler 가 TLS 전용이라는 것이다. 첫 바이트가 핸드셰이크인지
// 보고 걸러 내고 ParseClientHello 가 성공해야 흐름을 닫으므로 HTTP 에는 그대로 못 쓴다.
//
// 그래서 한계가 남는다. User-Agent 가 아주 긴 요청은 헤더가 두 세그먼트로 쪼개져 뒤쪽 값을
// 놓칠 수 있다. 그때도 앞의 요청 라인과 Host 는 얻으므로 "어디에 접속했나" 는 남는다.
// 빈 줄(헤더 끝)을 못 봤다고 false 를 주지 않는 것도 같은 이유다.
func ParseHTTP(payload []byte) (HTTPMessage, bool) {
	line, rest, ok := nextLine(payload, httpMaxLine)
	if !ok {
		return HTTPMessage{}, false
	}
	if msg, ok := parseStatusLine(line); ok {
		return msg, true
	}
	msg, ok := parseRequestLine(line)
	if !ok {
		return HTTPMessage{}, false
	}
	msg.Host, msg.UserAgent = scanHeaders(rest)
	return msg, true
}

// nextLine 은 다음 줄과 그 뒤를 돌려준다. limit 안에서 줄이 끝나지 않으면 false 다.
//
// 줄바꿈은 CRLF 가 규격이지만 LF 만 보내는 구현도 있어 둘 다 받는다.
func nextLine(b []byte, limit int) (line, rest []byte, ok bool) {
	search := b
	if len(search) > limit {
		search = search[:limit]
	}
	i := bytes.IndexByte(search, '\n')
	if i < 0 {
		return nil, nil, false
	}
	return bytes.TrimSuffix(search[:i], []byte("\r")), b[i+1:], true
}

// parseRequestLine 은 "GET /path HTTP/1.1" 을 읽는다.
func parseRequestLine(line []byte) (HTTPMessage, bool) {
	method, rest, ok := bytes.Cut(line, []byte(" "))
	if !ok || !isKnownMethod(method) {
		return HTTPMessage{}, false
	}
	// 요청 대상에는 공백이 들어갈 수 없다. 들어 있으면 버전 자리에 대상의 뒷부분이 오고
	// 아래 검사에서 걸린다. 따로 볼 필요가 없다.
	target, version, ok := bytes.Cut(rest, []byte(" "))
	if !ok || !isHTTP1(version) || len(target) == 0 {
		return HTTPMessage{}, false
	}
	path := cleanPath(target)
	if path == "" {
		return HTTPMessage{}, false
	}
	return HTTPMessage{Method: string(method), Path: path}, true
}

// parseStatusLine 은 "HTTP/1.1 200 OK" 를 읽는다.
//
// 사유 구절("OK", "Not Found")은 버린다. 보내는 쪽이 아무 문자열이나 넣을 수 있는데 코드가
// 이미 같은 뜻을 담고 있어서 값을 늘릴 뿐이다.
func parseStatusLine(line []byte) (HTTPMessage, bool) {
	version, rest, ok := bytes.Cut(line, []byte(" "))
	if !ok || !isHTTP1(version) {
		return HTTPMessage{}, false
	}
	code, ok := statusCode(rest)
	if !ok {
		return HTTPMessage{}, false
	}
	return HTTPMessage{IsResponse: true, StatusCode: code}, true
}

// statusCode 는 상태 줄에서 세 자리 코드를 읽는다.
func statusCode(b []byte) (int, bool) {
	if len(b) < 3 {
		return 0, false
	}
	// 코드 뒤에는 공백이거나 줄 끝이어야 한다. "2000" 같은 것을 200 으로 읽으면 안 된다.
	if len(b) > 3 && b[3] != ' ' {
		return 0, false
	}
	code := 0
	for _, c := range b[:3] {
		if c < '0' || c > '9' {
			return 0, false
		}
		code = code*10 + int(c-'0')
	}
	if code < 100 || code > 599 {
		return 0, false
	}
	return code, true
}

// isKnownMethod 는 요청으로 인정할 메서드인지 본다.
//
// 화이트리스트로 두는 이유는 아무 텍스트나 HTTP 요청으로 읽히면 안 되기 때문이다. 캡처에는
// 온갖 프로토콜이 섞여 들어오고 그중 공백이 든 첫 줄은 얼마든지 있다. 한 번 오인하면
// 있지도 않은 접속 기록이 이벤트로 올라가 조사하는 사람을 엉뚱한 데로 보낸다.
// 메서드는 대소문자를 구분하는 값이라 그대로 비교한다.
func isKnownMethod(m []byte) bool {
	switch string(m) {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
		return true
	}
	return false
}

// isHTTP1 은 버전 표기가 우리가 읽을 수 있는 것인지 본다.
//
// HTTP/2 와 HTTP/3 은 헤더가 바이너리라 이 파서로 읽을 수 없다. 평문 h2c 업그레이드의
// 프리페이스("PRI * HTTP/2.0")도 메서드 검사에서 이미 걸린다.
func isHTTP1(v []byte) bool {
	switch string(v) {
	case "HTTP/1.1", "HTTP/1.0":
		return true
	}
	return false
}

// cleanPath 는 요청 대상에서 질의 문자열과 프래그먼트를 뗀다.
//
// **이건 성능이 아니라 방침 때문이다.** URL 질의에는 인증 토큰, 세션 ID, 검색어 같은 것이
// 흔히 들어간다. 그걸 서버로 올리면 수집이 아니라 감시가 된다. 조사에 필요한 것은
// "이 프로세스가 저 호스트의 이 경로를 불렀다" 까지고, 경로만으로 거기까지는 다 알 수 있다.
func cleanPath(target []byte) string {
	if i := bytes.IndexAny(target, "?#"); i >= 0 {
		target = target[:i]
	}
	if len(target) > httpMaxPath {
		target = target[:httpMaxPath]
	}
	return printableValue(target)
}

// scanHeaders 는 Host 와 User-Agent 만 찾는다.
//
// **다른 헤더는 이름조차 보지 않는다.** Authorization, Cookie, Proxy-Authorization 에는
// 자격 증명이 그대로 들어 있다. 헤더를 전부 훑어 담아 두고 나중에 거르는 구조로 만들면
// 거르는 목록에서 빠진 헤더 하나가 곧바로 유출이 된다. 필요한 둘만 이름으로 집어 가면
// 애초에 그런 일이 생길 자리가 없다.
//
// 둘 다 찾으면 즉시 멈춘다. 뒤쪽 헤더는 우리가 쓸 것이 없다.
func scanHeaders(b []byte) (host, userAgent string) {
	for range httpMaxHeaderLines {
		line, rest, ok := nextLine(b, httpMaxLine)
		if !ok {
			// 이 세그먼트에서 줄이 끝나지 않았다. 재조립하지 않으므로 여기까지다.
			return
		}
		if len(line) == 0 {
			return // 빈 줄이 헤더 영역의 끝이다
		}
		b = rest

		name, value, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			continue
		}
		switch {
		case host == "" && bytes.EqualFold(name, headerHost):
			// SNI 와 DNS 이름을 낮추는 것과 같은 규칙이다. 그래야 대시보드에서 한 도메인으로 묶인다.
			host = strings.ToLower(headerValue(value, httpMaxHost))
		case userAgent == "" && bytes.EqualFold(name, headerUserAgent):
			userAgent = headerValue(value, httpMaxUserAgent)
		}
		if host != "" && userAgent != "" {
			return
		}
	}
	return
}

// headerValue 는 헤더 값의 앞뒤 공백을 떼고 상한까지 자른다.
func headerValue(v []byte, max int) string {
	v = bytes.TrimSpace(v)
	if len(v) > max {
		v = v[:max]
	}
	return printableValue(v)
}

// printableValue 는 제어 문자가 섞인 값을 버린다.
//
// 이 값들은 보내는 쪽이 정한다. 제어 문자를 그대로 이벤트에 실으면 로그 한 줄이 여러 줄로
// 보이게 만들어 기록을 흐릴 수 있다. 조작된 값은 조사에 쓸모도 없으니 통째로 버린다.
func printableValue(v []byte) string {
	for _, c := range v {
		if c < 0x20 || c == 0x7f {
			return ""
		}
	}
	return string(v)
}
