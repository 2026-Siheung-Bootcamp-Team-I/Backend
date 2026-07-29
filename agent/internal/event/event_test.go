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

func TestProcessEvent(t *testing.T) {
	f := Factory{Host: "mac-1"}
	got := decode(t, f.Process(at, "/bin/sh", "sh -c whoami", "bash"))

	want := map[string]any{
		"host": "mac-1",
		"type": TypeProcess,
		// ts 는 초가 아니라 밀리초다. 초로 보내면 detector 의 5 분 윈도우가 통째로 어긋난다.
		"ts": float64(1753900000000),
		// process 는 전체 경로가 아니라 basename 이다. 룰이 basename 으로 비교한다.
		"process": "sh",
		"parent":  "bash",
		"cmdline": "sh -c whoami",
	}
	for key, value := range want {
		if got[key] != value {
			t.Errorf("%s = %v, want %v", key, got[key], value)
		}
	}
}

func TestScriptEvent(t *testing.T) {
	f := Factory{Host: "mac-1"}
	got := decode(t, f.Script(at, "/bin/bash", "bash /tmp/x.sh", "sshd"))

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
}

func TestNetworkEvent(t *testing.T) {
	f := Factory{Host: "win-1"}
	got := decode(t, f.Network(at, `C:\Windows\System32\curl.exe`, "203.0.113.9", 443))

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
}

func TestFileEvent(t *testing.T) {
	f := Factory{Host: "mac-1"}
	got := decode(t, f.File(at, "/Library/LaunchDaemons/evil.plist"))

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
}

func TestTenantIdIsNeverSent(t *testing.T) {
	// 엔드포인트가 보낸 조직 태그를 믿으면 다른 조직 데이터에 섞어 넣을 수 있다.
	// 서버가 node_key 로 풀어 심으므로 에이전트는 이 필드를 아예 갖지 않는다.
	f := Factory{Host: "mac-1"}
	got := decode(t, f.Process(at, "/bin/sh", "sh", "bash"))

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
	got := decode(t, f.Process(at, "/bin/sh", "sh", "bash"))

	for _, field := range []string{"destIp", "destPort"} {
		if _, exists := got[field]; exists {
			t.Errorf("process 이벤트에 %s 가 들어있다", field)
		}
	}
}
