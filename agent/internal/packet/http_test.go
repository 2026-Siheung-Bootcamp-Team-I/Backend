package packet

import (
	"crypto/tls"
	"strings"
	"testing"
)

// request 는 요청 헤더를 조립한다. 마지막 빈 줄까지 붙여 실제 요청과 같은 모양으로 만든다.
func request(line string, headers ...string) []byte {
	return []byte(line + "\r\n" + strings.Join(headers, "\r\n") + "\r\n\r\n")
}

func TestParseHTTPRequest(t *testing.T) {
	cases := map[string]struct {
		raw  []byte
		want HTTPMessage
	}{
		"GET": {
			request("GET /index.html HTTP/1.1",
				"Host: example.com",
				"User-Agent: curl/8.4.0",
				"Accept: */*"),
			HTTPMessage{Method: "GET", Host: "example.com", Path: "/index.html", UserAgent: "curl/8.4.0"},
		},
		"POST": {
			request("POST /api/login HTTP/1.1",
				"Host: api.example.com",
				"Content-Length: 27",
				"User-Agent: Go-http-client/1.1"),
			HTTPMessage{Method: "POST", Host: "api.example.com", Path: "/api/login", UserAgent: "Go-http-client/1.1"},
		},
		"HTTP/1.0": {
			request("GET / HTTP/1.0", "Host: old.example.com"),
			HTTPMessage{Method: "GET", Host: "old.example.com", Path: "/"},
		},
		"LF 만 쓰는 구현": {
			[]byte("GET /lf HTTP/1.1\nHost: lf.example.com\n\n"),
			HTTPMessage{Method: "GET", Host: "lf.example.com", Path: "/lf"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, ok := ParseHTTP(tc.raw)
			if !ok {
				t.Fatal("ParseHTTP 가 false 를 돌려줬다")
			}
			if got != tc.want {
				t.Errorf("msg = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestParseHTTPAllMethods(t *testing.T) {
	for _, method := range []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"} {
		msg, ok := ParseHTTP(request(method+" /m HTTP/1.1", "Host: m.example.com"))
		if !ok {
			t.Fatalf("%s 에서 false", method)
		}
		if msg.Method != method {
			t.Errorf("Method = %q, want %q", msg.Method, method)
		}
	}
}

// 질의 문자열에는 토큰과 세션 ID 가 흔히 들어간다. 그걸 서버로 올리면 수집이 아니라 감시다.
func TestParseHTTPStripsQueryAndFragment(t *testing.T) {
	cases := map[string]string{
		"/search?q=secret":                  "/search",
		"/oauth/callback?code=abc&state=xy": "/oauth/callback",
		"/page#section":                     "/page",
		"/a?b=1#c":                          "/a",
		"/?token=eyJhbGciOi":                "/",
		"/plain":                            "/plain",
	}
	for target, want := range cases {
		t.Run(target, func(t *testing.T) {
			msg, ok := ParseHTTP(request("GET "+target+" HTTP/1.1", "Host: example.com"))
			if !ok {
				t.Fatal("ParseHTTP 가 false 를 돌려줬다")
			}
			if msg.Path != want {
				t.Errorf("Path = %q, want %q", msg.Path, want)
			}
			if strings.ContainsAny(msg.Path, "?#") {
				t.Errorf("Path 에 질의나 프래그먼트가 남았다: %q", msg.Path)
			}
		})
	}
}

func TestParseHTTPResponse(t *testing.T) {
	cases := map[string]int{
		"HTTP/1.1 200 OK\r\n\r\n":                            200,
		"HTTP/1.1 404 Not Found\r\nServer: nginx\r\n\r\n":    404,
		"HTTP/1.0 301 Moved Permanently\r\n\r\n":             301,
		"HTTP/1.1 500 Internal Server Error\r\n\r\n":         500,
		"HTTP/1.1 204\r\n\r\n":                               204, // 사유 구절이 없어도 된다
		"HTTP/1.1 200 OK\r\nSet-Cookie: session=abc\r\n\r\n": 200,
	}
	for raw, want := range cases {
		t.Run(strings.SplitN(raw, "\r\n", 2)[0], func(t *testing.T) {
			msg, ok := ParseHTTP([]byte(raw))
			if !ok {
				t.Fatal("ParseHTTP 가 false 를 돌려줬다")
			}
			if !msg.IsResponse {
				t.Error("IsResponse 가 false 다")
			}
			if msg.StatusCode != want {
				t.Errorf("StatusCode = %d, want %d", msg.StatusCode, want)
			}
			if msg.Method != "" || msg.Path != "" {
				t.Errorf("응답인데 요청 값이 찼다: %+v", msg)
			}
		})
	}
}

func TestParseHTTPRejectsBadStatusLine(t *testing.T) {
	cases := map[string]string{
		"코드가 세 자리가 아님": "HTTP/1.1 2000 OK\r\n\r\n",
		"코드가 숫자가 아님":   "HTTP/1.1 abc OK\r\n\r\n",
		"범위 밖(너무 작음)":  "HTTP/1.1 099 Weird\r\n\r\n",
		"범위 밖(너무 큼)":   "HTTP/1.1 600 Weird\r\n\r\n",
		"코드가 없음":       "HTTP/1.1 \r\n\r\n",
		"HTTP/2":       "HTTP/2.0 200 OK\r\n\r\n",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if msg, ok := ParseHTTP([]byte(raw)); ok {
				t.Errorf("true 를 줬다: %+v", msg)
			}
		})
	}
}

// 헤더 이름은 대소문자를 가리지 않는다. 정규화하지 않고 그대로 비교하면 절반을 놓친다.
func TestParseHTTPHeaderCaseInsensitive(t *testing.T) {
	msg, ok := ParseHTTP(request("GET / HTTP/1.1",
		"HOST: mixed.example.com",
		"user-agent: lowercase/1.0"))
	if !ok {
		t.Fatal("ParseHTTP 가 false 를 돌려줬다")
	}
	if msg.Host != "mixed.example.com" {
		t.Errorf("Host = %q", msg.Host)
	}
	if msg.UserAgent != "lowercase/1.0" {
		t.Errorf("UserAgent = %q", msg.UserAgent)
	}
}

// Host 는 SNI, DNS 이름과 같은 값이라 같은 규칙으로 낮춘다. 그래야 한 도메인으로 묶인다.
func TestParseHTTPNormalizesHost(t *testing.T) {
	msg, ok := ParseHTTP(request("GET / HTTP/1.1", "Host: WWW.Example.COM"))
	if !ok {
		t.Fatal("ParseHTTP 가 false 를 돌려줬다")
	}
	if msg.Host != "www.example.com" {
		t.Errorf("Host = %q, want www.example.com", msg.Host)
	}
}

// User-Agent 는 대문자를 낮추지 않는다. 값 자체가 구분에 쓰이는 문자열이다.
func TestParseHTTPKeepsUserAgentCase(t *testing.T) {
	const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	msg, ok := ParseHTTP(request("GET / HTTP/1.1", "Host: h", "User-Agent: "+ua))
	if !ok {
		t.Fatal("ParseHTTP 가 false 를 돌려줬다")
	}
	if msg.UserAgent != ua {
		t.Errorf("UserAgent = %q, want %q", msg.UserAgent, ua)
	}
}

// 헤더가 없거나 순서가 달라도 요청 라인은 남아야 한다. 없는 헤더가 오류는 아니다.
func TestParseHTTPHeaderVariations(t *testing.T) {
	cases := map[string]struct {
		raw           []byte
		host, agent   string
		wantParsePath string
	}{
		"헤더 없음": {
			[]byte("GET /nohdr HTTP/1.1\r\n\r\n"), "", "", "/nohdr",
		},
		"헤더 영역이 시작도 안 함": {
			[]byte("GET /bare HTTP/1.1\r\n"), "", "", "/bare",
		},
		"User-Agent 가 Host 보다 먼저": {
			request("GET /order HTTP/1.1", "User-Agent: first/1.0", "Accept: */*", "Host: order.example.com"),
			"order.example.com", "first/1.0", "/order",
		},
		"Host 만": {
			request("GET /onlyhost HTTP/1.1", "Host: only.example.com"),
			"only.example.com", "", "/onlyhost",
		},
		"값 앞뒤 공백": {
			request("GET /ws HTTP/1.1", "Host:   ws.example.com  ", "User-Agent:\tagent/1.0"),
			"ws.example.com", "agent/1.0", "/ws",
		},
		"콜론 없는 줄": {
			request("GET /odd HTTP/1.1", "garbage", "Host: odd.example.com"),
			"odd.example.com", "", "/odd",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			msg, ok := ParseHTTP(tc.raw)
			if !ok {
				t.Fatal("ParseHTTP 가 false 를 돌려줬다")
			}
			if msg.Path != tc.wantParsePath {
				t.Errorf("Path = %q, want %q", msg.Path, tc.wantParsePath)
			}
			if msg.Host != tc.host {
				t.Errorf("Host = %q, want %q", msg.Host, tc.host)
			}
			if msg.UserAgent != tc.agent {
				t.Errorf("UserAgent = %q, want %q", msg.UserAgent, tc.agent)
			}
		})
	}
}

// 우리가 담는 헤더는 둘뿐이다. 자격 증명이 든 헤더는 이름조차 보지 않는다.
func TestParseHTTPDoesNotCarrySecrets(t *testing.T) {
	const secret = "Bearer eyJhbGciOiJIUzI1NiJ9.super-secret"
	msg, ok := ParseHTTP(request("GET /me HTTP/1.1",
		"Host: api.example.com",
		"Authorization: "+secret,
		"Cookie: session=deadbeef; csrf=cafe",
		"Proxy-Authorization: Basic dXNlcjpwYXNz",
		"User-Agent: app/2.0"))
	if !ok {
		t.Fatal("ParseHTTP 가 false 를 돌려줬다")
	}
	for field, v := range map[string]string{"Host": msg.Host, "Path": msg.Path, "UserAgent": msg.UserAgent, "Method": msg.Method} {
		for _, leak := range []string{"eyJhbGciOiJIUzI1NiJ9", "deadbeef", "dXNlcjpwYXNz", "Bearer", "Basic"} {
			if strings.Contains(v, leak) {
				t.Errorf("%s 에 %q 가 들어갔다: %q", field, leak, v)
			}
		}
	}
	if msg.UserAgent != "app/2.0" || msg.Host != "api.example.com" {
		t.Errorf("정상 값을 놓쳤다: %+v", msg)
	}
}

// 메서드 화이트리스트가 없으면 공백이 든 아무 텍스트나 접속 기록이 된다.
func TestParseHTTPRejectsNonRequests(t *testing.T) {
	cases := map[string][]byte{
		"빈 입력":            {},
		"개행뿐":             []byte("\r\n"),
		"메서드가 아님":         []byte("HELO mail.example.com HTTP/1.1\r\n\r\n"),
		"소문자 메서드":         []byte("get / HTTP/1.1\r\n\r\n"),
		"메서드 접두사만 같음":     []byte("GETX / HTTP/1.1\r\n\r\n"),
		"h2c 프리페이스":       []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
		"버전이 없음":          []byte("GET /\r\n\r\n"),
		"버전이 HTTP 가 아님":   []byte("GET / RTSP/1.0\r\n\r\n"),
		"경로에 공백":          []byte("GET /a b HTTP/1.1\r\n\r\n"),
		"경로가 없음":          []byte("GET  HTTP/1.1\r\n\r\n"),
		"줄이 끝나지 않음":       []byte("GET /never-ends HTTP/1.1"),
		"SSH 배너":          []byte("SSH-2.0-OpenSSH_9.6\r\n"),
		"이진 쓰레기":          {0x00, 0x01, 0x02, 0x0a, 0xff},
		"경로가 제어 문자":       []byte("GET /a\x01b HTTP/1.1\r\n\r\n"),
		"DNS 질의":          dnsQuery(t, "example.com.", 1),
		"메서드만 있고 나머지가 잘림": []byte("GET"),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if msg, ok := ParseHTTP(raw); ok {
				t.Errorf("true 를 줬다: %+v", msg)
			}
		})
	}
}

// HTTPS 를 HTTP 로 오인하면 접속 기록이 통째로 어긋난다. 첫 바이트부터 다르니 걸러야 한다.
func TestParseHTTPRejectsTLS(t *testing.T) {
	raw := clientHello(t, &tls.Config{ServerName: "example.com", NextProtos: []string{"h2", "http/1.1"}})

	if msg, ok := ParseHTTP(raw); ok {
		t.Errorf("ClientHello 를 HTTP 로 읽었다: %+v", msg)
	}
	// 잘린 조각도 마찬가지다. 우연히 개행 바이트가 섞여도 통과하면 안 된다.
	for i := range len(raw) {
		if _, ok := ParseHTTP(raw[:i]); ok {
			t.Fatalf("ClientHello 앞 %d 바이트를 HTTP 로 읽었다", i)
		}
	}
}

// 잘린 입력에서 panic 하지 않고, 요청 라인이 다 오기 전에는 값을 만들지 않는다.
func TestParseHTTPTruncated(t *testing.T) {
	raw := request("GET /truncated HTTP/1.1", "Host: t.example.com", "User-Agent: agent/1.0")

	for i := range len(raw) {
		msg, ok := ParseHTTP(raw[:i])
		if !ok {
			continue
		}
		// 요청 라인이 끝난 뒤로는 true 가 정상이다. 다만 값이 어긋나면 안 된다.
		if msg.Method != "GET" || msg.Path != "/truncated" {
			t.Fatalf("%d 바이트에서 msg = %+v", i, msg)
		}
		if msg.Host != "" && msg.Host != "t.example.com" {
			t.Fatalf("%d 바이트에서 Host = %q", i, msg.Host)
		}
	}
}

// 한 세그먼트에 헤더가 다 안 와도 요청 라인과 Host 는 얻는다. 재조립하지 않기로 한 근거다.
func TestParseHTTPFirstSegmentGivesHost(t *testing.T) {
	raw := request("GET /page HTTP/1.1",
		"Host: split.example.com",
		"User-Agent: "+strings.Repeat("A", 2000))

	// 1460 바이트는 이더넷 MSS 다. 실제 캡처에서 첫 세그먼트가 이 크기다.
	msg, ok := ParseHTTP(raw[:1460])
	if !ok {
		t.Fatal("첫 세그먼트에서 false 를 줬다")
	}
	if msg.Method != "GET" || msg.Path != "/page" || msg.Host != "split.example.com" {
		t.Errorf("msg = %+v", msg)
	}
}

// 상한이 없으면 보내는 쪽이 이벤트 하나의 크기를 정하게 된다.
func TestParseHTTPLimits(t *testing.T) {
	t.Run("요청 라인이 상한을 넘음", func(t *testing.T) {
		raw := []byte("GET /" + strings.Repeat("a", httpMaxLine) + " HTTP/1.1\r\nHost: big.example.com\r\n\r\n")
		if msg, ok := ParseHTTP(raw); ok {
			t.Errorf("상한을 넘은 요청 라인을 읽었다: len(Path)=%d", len(msg.Path))
		}
	})

	t.Run("경로가 길면 자른다", func(t *testing.T) {
		raw := request("GET /"+strings.Repeat("a", httpMaxPath+500)+" HTTP/1.1", "Host: long.example.com")
		msg, ok := ParseHTTP(raw)
		if !ok {
			t.Fatal("ParseHTTP 가 false 를 돌려줬다")
		}
		if len(msg.Path) != httpMaxPath {
			t.Errorf("len(Path) = %d, want %d", len(msg.Path), httpMaxPath)
		}
	})

	t.Run("User-Agent 가 길면 자른다", func(t *testing.T) {
		raw := request("GET / HTTP/1.1", "Host: h", "User-Agent: "+strings.Repeat("U", httpMaxUserAgent+500))
		msg, ok := ParseHTTP(raw)
		if !ok {
			t.Fatal("ParseHTTP 가 false 를 돌려줬다")
		}
		if len(msg.UserAgent) != httpMaxUserAgent {
			t.Errorf("len(UserAgent) = %d, want %d", len(msg.UserAgent), httpMaxUserAgent)
		}
	})

	t.Run("Host 가 길면 자른다", func(t *testing.T) {
		raw := request("GET / HTTP/1.1", "Host: "+strings.Repeat("h", httpMaxHost+500))
		msg, ok := ParseHTTP(raw)
		if !ok {
			t.Fatal("ParseHTTP 가 false 를 돌려줬다")
		}
		if len(msg.Host) != httpMaxHost {
			t.Errorf("len(Host) = %d, want %d", len(msg.Host), httpMaxHost)
		}
	})

	t.Run("헤더 줄이 너무 많음", func(t *testing.T) {
		// 상한 너머에 있는 Host 는 못 찾는 것이 정상이다. 그래도 요청 라인은 남는다.
		var b strings.Builder
		b.WriteString("GET /many HTTP/1.1\r\n")
		for range httpMaxHeaderLines + 10 {
			b.WriteString("X-Filler: 1\r\n")
		}
		b.WriteString("Host: late.example.com\r\n\r\n")

		msg, ok := ParseHTTP([]byte(b.String()))
		if !ok {
			t.Fatal("ParseHTTP 가 false 를 돌려줬다")
		}
		if msg.Path != "/many" {
			t.Errorf("Path = %q, want /many", msg.Path)
		}
		if msg.Host != "" {
			t.Errorf("상한 너머의 Host 를 읽었다: %q", msg.Host)
		}
	})

	t.Run("헤더 영역이 끝나지 않음", func(t *testing.T) {
		// 빈 줄이 영원히 안 오는 입력이다. 상한이 없으면 여기서 멈추지 못한다.
		raw := []byte("GET /noend HTTP/1.1\r\n" + strings.Repeat("X-Filler: 1\r\n", 100000))
		msg, ok := ParseHTTP(raw)
		if !ok {
			t.Fatal("ParseHTTP 가 false 를 돌려줬다")
		}
		if msg.Path != "/noend" {
			t.Errorf("Path = %q", msg.Path)
		}
	})
}

// 제어 문자가 든 헤더 값은 조작된 것이다. 그대로 실으면 로그 한 줄이 여러 줄로 보이게 된다.
func TestParseHTTPDropsControlCharacters(t *testing.T) {
	raw := []byte("GET /ctl HTTP/1.1\r\nHost: ok.example.com\x00evil\r\nUser-Agent: a\x1bb\r\n\r\n")

	msg, ok := ParseHTTP(raw)
	if !ok {
		t.Fatal("ParseHTTP 가 false 를 돌려줬다")
	}
	if msg.Host != "" {
		t.Errorf("Host = %q, want 빈 문자열", msg.Host)
	}
	if msg.UserAgent != "" {
		t.Errorf("UserAgent = %q, want 빈 문자열", msg.UserAgent)
	}
}

func TestParseHTTPFromFullFrame(t *testing.T) {
	raw := request("POST /upload HTTP/1.1", "Host: drop.example.net", "User-Agent: agent/1.0")
	frame := ethernet(etherTypeIPv4, ipv4(protoTCP, "10.0.0.2", "203.0.113.9", nil, tcp(51000, 80, nil, raw)))

	flow, payload, ok := Parse(frame, LinkEthernet)
	if !ok {
		t.Fatal("프레임을 벗기지 못했다")
	}
	if flow.DstPort != 80 {
		t.Fatalf("DstPort = %d, want 80", flow.DstPort)
	}

	msg, ok := ParseHTTP(payload)
	if !ok {
		t.Fatal("페이로드에서 HTTP 를 읽지 못했다")
	}
	if msg.Host != "drop.example.net" || msg.Path != "/upload" || msg.Method != "POST" {
		t.Errorf("msg = %+v", msg)
	}
}
