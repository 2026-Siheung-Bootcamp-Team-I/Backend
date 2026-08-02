package packet

import (
	"bytes"
	"strings"
)

// HTTPMessage 는 평문 HTTP 에서 뽑은 메타데이터다. 본문은 담지 않는다.
// 요청과 응답을 한 타입으로 다루고 IsResponse 로 어느 쪽인지 가린다.
type HTTPMessage struct {
	IsResponse bool
	Method     string // 요청일 때
	Host       string // Host 헤더
	Path       string // 요청 경로. 질의 문자열은 뗀다
	UserAgent  string
	StatusCode int // 응답일 때
}

const (
	// httpMaxLine 은 한 줄의 최대 길이다. 상한이 없으면 개행 없는 바이트 뭉치가 CPU 를 태운다.
	httpMaxLine = 8 * 1024
	// httpMaxHeaderLines 는 훑을 헤더 줄 수다.
	httpMaxHeaderLines = 32

	// 값마다 길이를 자른다. 안 자르면 이벤트 하나가 얼마나 커질지를 보내는 쪽이 정하게 된다.
	httpMaxPath      = 1024
	httpMaxHost      = 256
	httpMaxUserAgent = 512
)

var (
	headerHost      = []byte("host")
	headerUserAgent = []byte("user-agent")
)

// ParseHTTP 는 TCP 페이로드에서 평문 HTTP 의 메타데이터를 꺼낸다.
// 재조립하지 않는다. 첫 세그먼트에서 읽히는 것만 읽는다.
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

// parseStatusLine 은 "HTTP/1.1 200 OK" 를 읽는다. 사유 구절("OK", "Not Found")은 버린다.
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
// 목록을 넓히면 공백 든 첫 줄을 가진 아무 프로토콜이나 요청으로 오인해 없는 접속 기록이 올라간다.
// 메서드는 대소문자를 구분하는 값이라 그대로 비교한다.
func isKnownMethod(m []byte) bool {
	switch string(m) {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
		return true
	}
	return false
}

// isHTTP1 은 버전 표기가 우리가 읽을 수 있는 것인지 본다.
// HTTP/2 와 HTTP/3 을 여기 추가하면 바이너리 헤더를 텍스트로 읽어 엉뚱한 값이 나온다.
func isHTTP1(v []byte) bool {
	switch string(v) {
	case "HTTP/1.1", "HTTP/1.0":
		return true
	}
	return false
}

// cleanPath 는 요청 대상에서 질의 문자열과 프래그먼트를 뗀다.
// 안 떼면 URL 질의에 흔히 든 인증 토큰, 세션 ID, 검색어가 그대로 서버로 올라간다.
func cleanPath(target []byte) string {
	if i := bytes.IndexAny(target, "?#"); i >= 0 {
		target = target[:i]
	}
	if len(target) > httpMaxPath {
		target = target[:httpMaxPath]
	}
	return printableValue(target)
}

// scanHeaders 는 Host 와 User-Agent 만 찾는다. 다른 헤더는 이름조차 보지 않는다.
// 전부 담고 나중에 거르는 구조로 바꾸면 거르는 목록에서 빠진 헤더 하나가 곧바로 유출이 된다.
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
// 그대로 실으면 보내는 쪽이 로그 한 줄을 여러 줄로 보이게 만들어 기록을 흐릴 수 있다.
func printableValue(v []byte) string {
	for _, c := range v {
		if c < 0x20 || c == 0x7f {
			return ""
		}
	}
	return string(v)
}
