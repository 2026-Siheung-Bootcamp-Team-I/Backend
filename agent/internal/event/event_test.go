package event

import (
	"encoding/json"
	"testing"
	"time"
)

// 이벤트 형식은 docs/agent-protocol.md 의 계약이자 detector 판정 입력 스키마다.
// 필드 이름 하나가 어긋나면 서버에서 조용히 null 이 되고 룰이 발화하지 않는다.

var at = time.Unix(1753900000, 0)

func decode(t *testing.T, e Event) map[string]any {
	t.Helper()
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

// detailOf 는 이벤트의 detail 문자열을 다시 맵으로 푼다.
// detail 이 비어 있으면 빈 맵이다. 키가 아예 없는 것과 값이 비어 있는 것을 같이 다루기 위해서다.
func detailOf(t *testing.T, got map[string]any) map[string]any {
	t.Helper()
	raw, ok := got["detail"].(string)
	if !ok || raw == "" {
		return map[string]any{}
	}
	var detail map[string]any
	if err := json.Unmarshal([]byte(raw), &detail); err != nil {
		t.Fatalf("detail 이 JSON 이 아니다: %v", err)
	}
	return detail
}

func TestProcessEvent(t *testing.T) {
	f := Factory{Host: "mac-1"}
	got := decode(t, f.Process(at, ProcessInfo{
		Path:    "/bin/sh",
		Cmdline: "sh -c whoami",
		Parent:  "bash",
		PID:     4242,
		PPID:    501,
		SHA256:  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}))

	want := map[string]any{
		"host": "mac-1",
		"type": TypeProcess,
		// ts 는 초가 아니라 밀리초다. 초로 보내면 detector 의 5 분 윈도우가 통째로 어긋난다.
		"ts": float64(1753900000000),
		// process 는 전체 경로가 아니라 basename 이다. 룰이 basename 으로 비교한다.
		"process": "sh",
		"parent":  "bash",
		"cmdline": "sh -c whoami",
		// sha256 은 detail 이 아니라 최상위다. 알려진 악성 해시로 조회하는 대상이라 컬럼이어야 한다.
		"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}
	for key, value := range want {
		if got[key] != value {
			t.Errorf("%s = %v, want %v", key, got[key], value)
		}
	}

	detail := detailOf(t, got)
	if detail["pid"] != float64(4242) {
		t.Errorf("detail.pid = %v, want 4242", detail["pid"])
	}
	if detail["ppid"] != float64(501) {
		t.Errorf("detail.ppid = %v, want 501", detail["ppid"])
	}
}

func TestScriptEvent(t *testing.T) {
	f := Factory{Host: "mac-1"}
	got := decode(t, f.Script(at, ProcessInfo{
		Path:    "/bin/bash",
		Cmdline: "bash /tmp/x.sh",
		Parent:  "sshd",
		PID:     10,
		PPID:    1,
	}))

	if got["type"] != TypeScript {
		t.Errorf("type = %v, want %v", got["type"], TypeScript)
	}
	if got["process"] != "bash" {
		t.Errorf("process = %v, want bash", got["process"])
	}
	// R3 룰이 cmdline 의 경로 인자에서 /tmp/ 를 찾는다.
	if got["cmdline"] != "bash /tmp/x.sh" {
		t.Errorf("cmdline = %v", got["cmdline"])
	}
	// script 도 process 와 같은 부가 식별자를 실어야 한다. 컬럼 구조가 같기 때문이다.
	detail := detailOf(t, got)
	if detail["pid"] != float64(10) || detail["ppid"] != float64(1) {
		t.Errorf("detail = %v, want pid 10 / ppid 1", detail)
	}
}

func TestNetworkEvent(t *testing.T) {
	f := Factory{Host: "win-1"}
	got := decode(t, f.Network(at, NetworkInfo{
		ProcessPath: `C:\Windows\System32\curl.exe`,
		PID:         777,
		Protocol:    ProtocolTCP,
		DestIP:      "203.0.113.9",
		DestPort:    443,
	}))

	if got["type"] != TypeNetwork {
		t.Errorf("type = %v, want %v", got["type"], TypeNetwork)
	}
	// 윈도우 경로 구분자도 basename 으로 잘려야 한다.
	if got["process"] != "curl.exe" {
		t.Errorf("process = %v, want curl.exe", got["process"])
	}
	if got["destIp"] != "203.0.113.9" {
		t.Errorf("destIp = %v", got["destIp"])
	}
	if got["destPort"] != float64(443) {
		t.Errorf("destPort = %v, want 443", got["destPort"])
	}

	detail := detailOf(t, got)
	if detail["pid"] != float64(777) {
		t.Errorf("detail.pid = %v, want 777", detail["pid"])
	}
	if detail["protocol"] != "tcp" {
		t.Errorf("detail.protocol = %v, want tcp", detail["protocol"])
	}
}

func TestFileEvent(t *testing.T) {
	f := Factory{Host: "mac-1"}
	got := decode(t, f.File(at, FileInfo{
		Path:   "/Library/LaunchDaemons/evil.plist",
		Action: FileActionCreate,
	}))

	if got["type"] != TypeFile {
		t.Errorf("type = %v, want %v", got["type"], TypeFile)
	}
	if got["process"] != "evil.plist" {
		t.Errorf("process = %v, want evil.plist", got["process"])
	}
	// R4 룰은 cmdline 에 담긴 전체 경로에서 /launchagents/ 같은 표식을 찾는다.
	if got["cmdline"] != "/Library/LaunchDaemons/evil.plist" {
		t.Errorf("cmdline = %v, want 전체 경로", got["cmdline"])
	}
	if detail := detailOf(t, got); detail["action"] != "CREATE" {
		t.Errorf("detail.action = %v, want CREATE", detail["action"])
	}
}

// 파일 동작은 상수로만 만든다. 센서마다 문자열을 적으면 오타 하나로 집계가 갈린다.
func TestFileActionsAreFixedStrings(t *testing.T) {
	want := map[string]string{
		FileActionCreate: "CREATE",
		FileActionWrite:  "WRITE",
		FileActionRename: "RENAME",
		FileActionDelete: "DELETE",
	}
	if len(want) != 4 {
		t.Fatalf("동작 상수가 겹친다: %v", want)
	}
	for got, expected := range want {
		if got != expected {
			t.Errorf("%q, want %q", got, expected)
		}
	}
}

func TestTenantIdIsNeverSent(t *testing.T) {
	// 엔드포인트가 보낸 조직 태그를 믿으면 다른 조직 데이터에 섞어 넣을 수 있다.
	// 서버가 node_key 로 풀어 심으므로 에이전트는 이 필드를 아예 갖지 않는다.
	f := Factory{Host: "mac-1"}
	got := decode(t, f.Process(at, ProcessInfo{Path: "/bin/sh", Cmdline: "sh", Parent: "bash"}))

	if _, exists := got["tenantId"]; exists {
		t.Error("tenantId 를 보내고 있다")
	}
}

func TestBasename(t *testing.T) {
	cases := map[string]string{
		"/bin/sh":                     "sh",
		`C:\Windows\System32\cmd.exe`: "cmd.exe",
		// ETW 는 전체 경로 없이 파일명만 주기도 한다. 그대로 통과해야 한다.
		"svchost.exe": "svchost.exe",
		"":            "",
		// 구분자로 끝나면 남는 게 없다. 빈 문자열이 되어도 터지지 않아야 한다.
		"/tmp/": "",
	}
	for input, want := range cases {
		if got := basename(input); got != want {
			t.Errorf("basename(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestEmptyOptionalFieldsAreOmitted(t *testing.T) {
	// process 이벤트에 destIp 가 섞여 나가면 detector 가 network 로 오해하지는 않지만
	// ClickHouse 에 의미 없는 컬럼이 쌓인다.
	f := Factory{Host: "mac-1"}
	got := decode(t, f.Process(at, ProcessInfo{Path: "/bin/sh", Cmdline: "sh", Parent: "bash"}))

	for _, field := range []string{"destIp", "destPort", "sha256"} {
		if _, exists := got[field]; exists {
			t.Errorf("process 이벤트에 %s 가 들어있다", field)
		}
	}
}

// 관측하지 못한 값은 키 자체를 빼야 한다. pid 0 이나 빈 action 을 실어 보내면
// ClickHouse 에 "0" 이 쌓여 진짜 pid 와 구분되지 않는다.
func TestUnknownDetailValuesAreDropped(t *testing.T) {
	f := Factory{Host: "mac-1"}

	cases := map[string]Event{
		"process": f.Process(at, ProcessInfo{Path: "/bin/sh"}),
		"file":    f.File(at, FileInfo{Path: "/tmp/x"}),
		"network": f.Network(at, NetworkInfo{ProcessPath: "/bin/sh", DestIP: "203.0.113.1", DestPort: 443}),
	}
	for name, e := range cases {
		t.Run(name, func(t *testing.T) {
			got := decode(t, e)
			if raw, exists := got["detail"]; exists {
				t.Errorf("담을 값이 없는데 detail 이 실려 나갔다: %v", raw)
			}
		})
	}
}

func TestDNSEvent(t *testing.T) {
	f := Factory{Host: "mac-1"}
	got := decode(t, f.DNS(at, DNSInfo{
		ProcessPath: "/usr/bin/curl",
		PID:         321,
		Protocol:    ProtocolUDP,
		Domain:      "evil.example.com",
	}, map[string]any{
		"queryType": "A",
		"answers":   []string{"203.0.113.9"},
	}))

	if got["type"] != TypeDNS {
		t.Errorf("type = %v, want %v", got["type"], TypeDNS)
	}
	if got["process"] != "curl" {
		t.Errorf("process = %v, want curl", got["process"])
	}
	// 도메인은 검색 대상이라 별도 필드다. detail 안에 묻으면 조회가 안 된다.
	if got["domain"] != "evil.example.com" {
		t.Errorf("domain = %v", got["domain"])
	}
	detail := detailOf(t, got)
	if detail["queryType"] != "A" {
		t.Errorf("detail.queryType = %v", detail["queryType"])
	}
	if detail["pid"] != float64(321) {
		t.Errorf("detail.pid = %v, want 321", detail["pid"])
	}
	if detail["protocol"] != "udp" {
		t.Errorf("detail.protocol = %v, want udp", detail["protocol"])
	}
}

// 센서가 넘긴 맵을 팩토리가 고치면 호출부가 재사용하는 맵이 몰래 바뀐다.
func TestDetailMapFromSensorIsNotMutated(t *testing.T) {
	f := Factory{Host: "mac-1"}
	detail := map[string]any{"queryType": "A"}

	f.DNS(at, DNSInfo{PID: 7, Protocol: ProtocolUDP, Domain: "example.com"}, detail)

	if len(detail) != 1 {
		t.Errorf("센서가 준 맵이 바뀌었다: %v", detail)
	}
}

func TestL7Event(t *testing.T) {
	f := Factory{Host: "mac-1"}
	got := decode(t, f.L7(at, L7Info{
		ProcessPath: "/usr/bin/curl",
		Protocol:    ProtocolTCP,
		Domain:      "api.example.com",
		DestIP:      "203.0.113.9",
		DestPort:    443,
	}, map[string]any{
		"issuer": "CN=Test CA",
	}))

	if got["type"] != TypeL7 {
		t.Errorf("type = %v, want %v", got["type"], TypeL7)
	}
	if got["domain"] != "api.example.com" {
		t.Errorf("domain = %v", got["domain"])
	}
	if got["destIp"] != "203.0.113.9" || got["destPort"] != float64(443) {
		t.Errorf("목적지 = %v:%v", got["destIp"], got["destPort"])
	}
	detail := detailOf(t, got)
	if detail["issuer"] != "CN=Test CA" {
		t.Errorf("detail.issuer = %v", detail["issuer"])
	}
	if detail["protocol"] != "tcp" {
		t.Errorf("detail.protocol = %v, want tcp", detail["protocol"])
	}
}

func TestDetailIsOmittedWhenEmpty(t *testing.T) {
	// 부가정보가 없는데 "{}" 나 "null" 을 보내면 ClickHouse 에 의미 없는 값이 쌓인다.
	f := Factory{Host: "mac-1"}
	got := decode(t, f.DNS(at, DNSInfo{ProcessPath: "/usr/bin/curl", Domain: "example.com"}, nil))

	if _, exists := got["detail"]; exists {
		t.Errorf("detail 이 비었는데 실려 나갔다: %v", got["detail"])
	}
}

func TestDomainIsOmittedForNonDomainEvents(t *testing.T) {
	f := Factory{Host: "mac-1"}
	for _, e := range []Event{
		f.Process(at, ProcessInfo{Path: "/bin/sh", Cmdline: "sh", Parent: "bash"}),
		f.Network(at, NetworkInfo{ProcessPath: "/bin/sh", Protocol: ProtocolTCP, DestIP: "203.0.113.1", DestPort: 443}),
		f.File(at, FileInfo{Path: "/tmp/x", Action: FileActionDelete}),
	} {
		got := decode(t, e)
		if _, exists := got["domain"]; exists {
			t.Errorf("%s 이벤트에 domain 이 들어있다", got["type"])
		}
	}
}
