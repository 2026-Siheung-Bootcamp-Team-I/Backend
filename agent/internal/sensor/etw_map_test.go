package sensor

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/event"
)

var (
	etwFactory = event.Factory{Host: "lab-win"}
	etwAt      = time.UnixMilli(1785341400000)
)

// fakeNamer 는 PID→이름 해석기를 대신한다. 표에 없는 PID 는 해석 실패로 본다.
type fakeNamer map[int]string

func (f fakeNamer) Name(pid int) string { return f[pid] }

func TestMapProcessDevicePath(t *testing.T) {
	props := map[string]string{
		"ProcessID":       "4242",
		"ParentProcessID": "1000",
		"ImageName":       `\Device\HarddiskVolume4\Windows\System32\notepad.exe`,
		"CommandLine":     `"C:\Windows\System32\notepad.exe" C:\Users\a\memo.txt`,
	}

	got, ok := MapProcess(etwFactory, etwAt, props, fakeNamer{1000: `C:\Windows\explorer.exe`})
	if !ok {
		t.Fatal("이벤트가 나오지 않았다")
	}
	want := event.Event{
		Host:    "lab-win",
		Type:    event.TypeProcess,
		TS:      1785341400000,
		Process: "notepad.exe",
		Parent:  "explorer.exe",
		// argv0 는 명령행이 들고 있던 값이 아니라 실행 파일 경로로 바뀐다.
		Cmdline: `\Device\HarddiskVolume4\Windows\System32\notepad.exe C:\Users\a\memo.txt`,
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

// ETW 는 전체 경로를 주지 못하므로 배선이 프로세스를 조회해 ImagePath 를 채운다.
// 그 값이 있으면 ImageName 보다 우선한다. 판정이 경로에 달려 있기 때문이다.
func TestMapProcessPrefersResolvedImagePath(t *testing.T) {
	props := map[string]string{
		"ImageName":   "run.exe",
		"ImagePath":   `C:\Users\a\AppData\Local\Temp\run.exe`,
		"CommandLine": `run.exe --quiet`,
	}

	got, ok := MapProcess(etwFactory, etwAt, props, fakeNamer{})
	if !ok {
		t.Fatal("이벤트가 나오지 않았다")
	}
	if got.Process != "run.exe" {
		t.Errorf("process = %q, want run.exe", got.Process)
	}
	want := `C:\Users\a\AppData\Local\Temp\run.exe --quiet`
	if got.Cmdline != want {
		t.Errorf("cmdline = %q, want %q", got.Cmdline, want)
	}
}

// detector 의 R2/R3 룰은 cmdline 의 첫 토큰만 떼어 표식을 찾는다(Rules.java executableHasMarker).
// Windows 명령행의 argv0 은 프로세스가 정하는 값이라 경로 없이 오는 일이 흔한데, 그대로 두면
// 실행 파일이 임시 경로에 있어도 CRITICAL 룰이 발화하지 않는다.
func TestMapProcessPutsExecutablePathInArgv0(t *testing.T) {
	tests := []struct {
		name  string
		image string
		cmd   string
		want  string
	}{
		{
			name:  "파일명만 있던 argv0 이 전체 경로로 바뀐다",
			image: `C:\Users\a\AppData\Local\Temp\evil.exe`,
			cmd:   `evil.exe -k`,
			want:  `C:\Users\a\AppData\Local\Temp\evil.exe -k`,
		},
		{
			name:  "따옴표로 감싼 argv0 도 바뀐다",
			image: `C:\Windows\Temp\a.exe`,
			cmd:   `"a.exe" --run`,
			want:  `C:\Windows\Temp\a.exe --run`,
		},
		{
			name:  "인자가 없어도 바뀐다",
			image: `C:\Windows\Temp\a.exe`,
			cmd:   `a.exe`,
			want:  `C:\Windows\Temp\a.exe`,
		},
		{
			name:  "장치 경로도 그대로 들어간다",
			image: `\Device\HarddiskVolume3\Windows\Temp\a.exe`,
			cmd:   `a.exe -x`,
			want:  `\Device\HarddiskVolume3\Windows\Temp\a.exe -x`,
		},
		{
			name:  "경로를 모르면 명령행을 건드리지 않는다",
			image: `powershell.exe`,
			cmd:   `powershell.exe -NoProfile -Command whoami`,
			want:  `powershell.exe -NoProfile -Command whoami`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			props := map[string]string{"ImageName": tc.image, "CommandLine": tc.cmd}
			got, ok := MapProcess(etwFactory, etwAt, props, fakeNamer{})
			if !ok {
				t.Fatal("이벤트가 나오지 않았다")
			}
			if got.Cmdline != tc.want {
				t.Errorf("cmdline = %q, want %q", got.Cmdline, tc.want)
			}
		})
	}
}

// argv0 을 바꾼 결과가 실제로 detector 룰에 걸리는 모양인지까지 본다.
// 첫 토큰에 표식이 없으면 R2 는 발화하지 않는다.
func TestMapProcessArgv0CarriesTempMarker(t *testing.T) {
	props := map[string]string{
		"ImageName":   "evil.exe",
		"ImagePath":   `C:\Users\a\AppData\Local\Temp\evil.exe`,
		"CommandLine": `evil.exe`,
	}
	got, ok := MapProcess(etwFactory, etwAt, props, fakeNamer{})
	if !ok {
		t.Fatal("이벤트가 나오지 않았다")
	}
	argv0 := strings.ToLower(strings.Fields(got.Cmdline)[0])
	if !strings.Contains(argv0, `appdata\local\temp`) {
		t.Errorf("argv0 = %q, 임시 경로 표식이 있어야 한다", argv0)
	}
}

// 전체 경로도 명령행도 못 구했으면 cmdline 은 비운다.
// 파일명만 담아 봐야 판정에 쓸 값이 아니면서 responder 의 조치 대상만 흐려 놓는다.
func TestMapProcessLeavesCmdlineEmptyWhenOnlyFilenameKnown(t *testing.T) {
	got, ok := MapProcess(etwFactory, etwAt, map[string]string{"ImageName": "svchost.exe"}, fakeNamer{})
	if !ok {
		t.Fatal("이벤트가 나오지 않았다")
	}
	if got.Process != "svchost.exe" {
		t.Errorf("process = %q, want svchost.exe", got.Process)
	}
	if got.Cmdline != "" {
		t.Errorf("cmdline = %q, want 빈 값", got.Cmdline)
	}
}

// ETW 의 ImageName 은 전체 경로가 아니라 파일명만 오기도 한다(실기기에서 "svchost.exe" 로 관측).
// 그래도 이벤트가 나와야 하고 인터프리터 분류도 그대로 되어야 한다.
func TestMapProcessImageNameWithoutPath(t *testing.T) {
	tests := []struct {
		name     string
		image    string
		wantType string
		wantProc string
	}{
		{"파일명만 온 일반 프로세스", "svchost.exe", event.TypeProcess, "svchost.exe"},
		{"파일명만 온 인터프리터", "powershell.exe", event.TypeScript, "powershell.exe"},
		{"장치 경로 인터프리터", `\Device\HarddiskVolume4\Windows\System32\cmd.exe`, event.TypeScript, "cmd.exe"},
		{"드라이브 경로 인터프리터", `C:\Windows\System32\WScript.exe`, event.TypeScript, "WScript.exe"},
		{"버전 붙은 파이썬", `C:\Python312\python3.12.exe`, event.TypeScript, "python3.12.exe"},
		{"mshta", "mshta.exe", event.TypeScript, "mshta.exe"},
		{"cscript", "cscript.exe", event.TypeScript, "cscript.exe"},
		{"이름이 비슷한 다른 프로그램", "powershellx.exe", event.TypeProcess, "powershellx.exe"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := MapProcess(etwFactory, etwAt, map[string]string{"ImageName": tc.image}, fakeNamer{})
			if !ok {
				t.Fatal("이벤트가 나오지 않았다")
			}
			if got.Type != tc.wantType {
				t.Errorf("type = %q, want %q", got.Type, tc.wantType)
			}
			if got.Process != tc.wantProc {
				t.Errorf("process = %q, want %q", got.Process, tc.wantProc)
			}
		})
	}
}

// CommandLine 은 ETW ProcessStart 에 실려 오지 않아 배선이 채워 넣는데, 그마저 실패하면
// 비워 두지 않고 이미지 경로로 물러난다. detector 가 경로만으로도 판정할 수 있어야 한다.
func TestMapProcessFallsBackToImageWhenNoCmdline(t *testing.T) {
	image := `\Device\HarddiskVolume4\Users\a\Downloads\run.exe`
	got, ok := MapProcess(etwFactory, etwAt, map[string]string{"ImageName": image}, fakeNamer{})
	if !ok {
		t.Fatal("이벤트가 나오지 않았다")
	}
	if got.Cmdline != image {
		t.Errorf("cmdline = %q, want %q", got.Cmdline, image)
	}
}

func TestMapProcessDropsEventWithoutImage(t *testing.T) {
	if _, ok := MapProcess(etwFactory, etwAt, map[string]string{"ProcessID": "10"}, fakeNamer{}); ok {
		t.Error("ImageName 없는 이벤트가 통과했다")
	}
}

// 부모 PID 를 이름으로 못 풀면 parent 는 비운다. 이벤트 자체는 버리지 않는다.
func TestMapProcessParentResolution(t *testing.T) {
	tests := []struct {
		name  string
		props map[string]string
		namer ProcessNamer
		want  string
	}{
		{
			name:  "해석 성공하면 basename 만 남는다",
			props: map[string]string{"ImageName": "a.exe", "ParentProcessID": "7"},
			namer: fakeNamer{7: `C:\Windows\System32\services.exe`},
			want:  "services.exe",
		},
		{
			name:  "이미 죽어 해석 못 하면 빈 값",
			props: map[string]string{"ImageName": "a.exe", "ParentProcessID": "7"},
			namer: fakeNamer{},
			want:  "",
		},
		{
			name:  "부모 PID 속성이 없으면 빈 값",
			props: map[string]string{"ImageName": "a.exe"},
			namer: fakeNamer{7: "services.exe"},
			want:  "",
		},
		{
			name:  "해석기가 없어도 죽지 않는다",
			props: map[string]string{"ImageName": "a.exe", "ParentProcessID": "7"},
			namer: nil,
			want:  "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := MapProcess(etwFactory, etwAt, tc.props, tc.namer)
			if !ok {
				t.Fatal("이벤트가 나오지 않았다")
			}
			if got.Parent != tc.want {
				t.Errorf("parent = %q, want %q", got.Parent, tc.want)
			}
		})
	}
}

func TestRedactSecrets(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "다음 토큰에 오는 값",
			in:   `net.exe user admin -Password hunter2 /add`,
			want: `net.exe user admin -Password <redacted> /add`,
		},
		{
			name: "등호로 붙은 값",
			in:   `tool.exe --password=hunter2 --verbose`,
			want: `tool.exe --password=<redacted> --verbose`,
		},
		{
			name: "콜론으로 붙은 값",
			in:   `tool.exe /Token:abc123`,
			want: `tool.exe /Token:<redacted>`,
		},
		{
			name: "EncodedCommand 의 base64",
			in:   `powershell.exe -EncodedCommand SQBFAFgA -NoProfile`,
			want: `powershell.exe -EncodedCommand <redacted> -NoProfile`,
		},
		{
			name: "줄인 -enc 도 가린다",
			in:   `powershell.exe -enc SQBFAFgA`,
			want: `powershell.exe -enc <redacted>`,
		},
		{
			name: "따옴표 안의 공백은 하나의 값이다",
			in:   `tool.exe -Token "a b c" next`,
			want: `tool.exe -Token <redacted> next`,
		},
		{
			name: "간격은 그대로 둔다",
			in:   `tool.exe   -Token   abc`,
			want: `tool.exe   -Token   <redacted>`,
		},
		{
			name: "옵션 접두사 없는 경로는 건드리지 않는다",
			in:   `C:\pass\token.exe run`,
			want: `C:\pass\token.exe run`,
		},
		{
			name: "값 없이 끝나도 깨지지 않는다",
			in:   `tool.exe -Password`,
			want: `tool.exe -Password`,
		},
		{
			name: "비밀값이 없으면 그대로",
			in:   `cmd.exe /c whoami`,
			want: `cmd.exe /c whoami`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := redactSecrets(tc.in); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMapProcessRedactsCmdline(t *testing.T) {
	props := map[string]string{
		"ImageName":   "powershell.exe",
		"CommandLine": `powershell.exe -EncodedCommand SQBFAFgA`,
	}
	got, ok := MapProcess(etwFactory, etwAt, props, fakeNamer{})
	if !ok {
		t.Fatal("이벤트가 나오지 않았다")
	}
	if got.Cmdline != `powershell.exe -EncodedCommand <redacted>` {
		t.Errorf("cmdline = %q", got.Cmdline)
	}
}

func TestMapNetwork(t *testing.T) {
	props := map[string]string{"PID": "4242", "daddr": "203.0.113.7", "dport": "443", "saddr": "192.168.0.5", "sport": "51000"}

	got, ok := MapNetwork(etwFactory, etwAt, props, fakeNamer{4242: `C:\Windows\System32\curl.exe`})
	if !ok {
		t.Fatal("이벤트가 나오지 않았다")
	}
	want := event.Event{
		Host:     "lab-win",
		Type:     event.TypeNetwork,
		TS:       1785341400000,
		Process:  "curl.exe",
		DestIP:   "203.0.113.7",
		DestPort: 443,
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

// 사설/루프백 목적지는 탐지에 쓸 값이 아니라 버린다. osquery 쿼리도 같은 조건이었다.
func TestMapNetworkFiltersNonRoutable(t *testing.T) {
	dropped := []string{
		"127.0.0.1", "127.9.9.9", "::1", "0.0.0.0", "::",
		"10.1.2.3", "172.16.0.9", "172.31.255.1", "192.168.1.10",
		"169.254.1.1", "fe80::1", "224.0.0.251", "fd00::1",
		"", "not-an-ip", "0x1234",
	}
	for _, ip := range dropped {
		if _, ok := MapNetwork(etwFactory, etwAt, map[string]string{"PID": "1", "daddr": ip, "dport": "80"}, fakeNamer{1: "a.exe"}); ok {
			t.Errorf("%q 가 통과했다", ip)
		}
	}

	kept := []string{"203.0.113.7", "8.8.8.8", "172.32.0.1", "2001:db8::1"}
	for _, ip := range kept {
		if _, ok := MapNetwork(etwFactory, etwAt, map[string]string{"PID": "1", "daddr": ip, "dport": "80"}, fakeNamer{1: "a.exe"}); !ok {
			t.Errorf("%q 가 걸러졌다", ip)
		}
	}
}

// 공인 IP 판정은 netsnap 의 IsPublic 하나로 통일한다. 여기서 따로 구현하면 같은 목적지를
// Windows 와 macOS 가 다르게 걸러 내는 상태가 조용히 생긴다.
func TestMapNetworkUsesIsPublic(t *testing.T) {
	for _, ip := range []string{"203.0.113.7", "10.1.2.3", "127.0.0.1", "2001:db8::1", "fe80::1", "not-an-ip"} {
		props := map[string]string{"PID": "1", "daddr": ip, "dport": "80"}
		_, ok := MapNetwork(etwFactory, etwAt, props, fakeNamer{1: "a.exe"})
		if ok != IsPublic(ip) {
			t.Errorf("%q: MapNetwork ok = %v, IsPublic = %v", ip, ok, IsPublic(ip))
		}
	}
}

// PID 해석에 실패해도 목적지 IP 판정은 살려야 하므로 프로세스명만 비우고 내보낸다.
func TestMapNetworkKeepsEventWhenPIDUnresolved(t *testing.T) {
	got, ok := MapNetwork(etwFactory, etwAt, map[string]string{"PID": "999", "daddr": "203.0.113.7", "dport": "443"}, fakeNamer{})
	if !ok {
		t.Fatal("이벤트가 나오지 않았다")
	}
	if got.Process != "" {
		t.Errorf("process = %q, want 빈 값", got.Process)
	}
	if got.DestIP != "203.0.113.7" || got.DestPort != 443 {
		t.Errorf("목적지가 어긋났다: %+v", got)
	}
}

func TestMapNetworkBadPort(t *testing.T) {
	for _, port := range []string{"", "abc", "-1", "70000"} {
		got, ok := MapNetwork(etwFactory, etwAt, map[string]string{"PID": "1", "daddr": "203.0.113.7", "dport": port}, fakeNamer{1: "a.exe"})
		if !ok {
			t.Fatalf("port %q: 이벤트가 나오지 않았다", port)
		}
		if got.DestPort != 0 {
			t.Errorf("port %q: destPort = %d, want 0", port, got.DestPort)
		}
	}
}

func TestMapFile(t *testing.T) {
	watch := []string{
		`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`,
		`C:\Users\a\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`,
	}

	tests := []struct {
		name string
		path string
		want bool
	}{
		{"장치 경로가 감시 경로 아래", `\Device\HarddiskVolume3\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\evil.lnk`, true},
		{"드라이브 경로가 감시 경로 아래", `C:\Users\a\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\evil.lnk`, true},
		{"대소문자가 달라도 통과", `\DEVICE\HARDDISKVOLUME3\programdata\MICROSOFT\windows\Start Menu\Programs\startup\x.lnk`, true},
		{`\??\ 접두어가 붙어도 통과`, `\??\C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\x.lnk`, true},
		{"감시 경로 자체", `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`, true},
		{"감시 경로 밖", `\Device\HarddiskVolume3\Windows\Temp\x.txt`, false},
		{"이름만 겹치는 형제 경로", `\Device\HarddiskVolume3\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUpOther\x.lnk`, false},
		{"빈 경로", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := MapFile(etwFactory, etwAt, map[string]string{"FileName": tc.path}, watch)
			if ok != tc.want {
				t.Fatalf("ok = %v, want %v", ok, tc.want)
			}
			if !ok {
				return
			}
			if got.Type != event.TypeFile {
				t.Errorf("type = %q", got.Type)
			}
			// detector 의 T1547 룰이 전체 경로를 보므로 cmdline 에 경로가 그대로 남아야 한다.
			if got.Cmdline != tc.path {
				t.Errorf("cmdline = %q, want %q", got.Cmdline, tc.path)
			}
		})
	}
}

// 감시 경로가 비면 아무것도 내보내지 않는다. 기준 없이 전부 흘리면 버퍼가 파일 이벤트로 찬다.
func TestMapFileDropsEverythingWithoutWatchPaths(t *testing.T) {
	for _, watch := range [][]string{nil, {}, {""}, {"   "}} {
		if _, ok := MapFile(etwFactory, etwAt, map[string]string{"FileName": `C:\Users\a\x.txt`}, watch); ok {
			t.Errorf("watch=%v 인데 이벤트가 나왔다", watch)
		}
	}
}

// dnsDetail 은 이벤트의 detail JSON 을 풀어 준다. detail 은 문자열로 실려 나가므로
// 값 하나를 보려면 매번 풀어야 한다.
func dnsDetail(t *testing.T, e event.Event) map[string]any {
	t.Helper()
	if e.Detail == "" {
		return nil
	}
	var detail map[string]any
	if err := json.Unmarshal([]byte(e.Detail), &detail); err != nil {
		t.Fatalf("detail 이 JSON 이 아니다: %v (%q)", err, e.Detail)
	}
	return detail
}

// 질의 완료(3008) 속성 맵이 그대로 dns 이벤트가 되는지 본다.
func TestMapDNS(t *testing.T) {
	props := map[string]string{
		"QueryName":    "api.example.com",
		"QueryType":    "1",
		"QueryOptions": "0",
		"QueryStatus":  "0",
		"QueryResults": "203.0.113.9;203.0.113.10;",
	}

	got, ok := MapDNS(etwFactory, etwAt, props, 4242, fakeNamer{4242: `C:\Program Files\browser\chrome.exe`})
	if !ok {
		t.Fatal("이벤트가 나오지 않았다")
	}
	if got.Type != event.TypeDNS || got.Host != "lab-win" || got.TS != 1785341400000 {
		t.Errorf("got %+v", got)
	}
	if got.Process != "chrome.exe" {
		t.Errorf("process = %q, want chrome.exe", got.Process)
	}
	// 도메인은 검색 대상이라 별도 필드다. detail 안에 묻으면 조회가 안 된다.
	if got.Domain != "api.example.com" {
		t.Errorf("domain = %q", got.Domain)
	}

	detail := dnsDetail(t, got)
	if detail["queryType"] != "A" {
		t.Errorf("detail.queryType = %v, want A", detail["queryType"])
	}
	if detail["status"] != float64(0) {
		t.Errorf("detail.status = %v, want 0", detail["status"])
	}
	want := []any{"203.0.113.9", "203.0.113.10"}
	if !reflect.DeepEqual(detail["answers"], want) {
		t.Errorf("detail.answers = %v, want %v", detail["answers"], want)
	}
}

// 같은 도메인이 표기 때문에 둘로 갈리면 대시보드 집계가 못 쓰게 된다.
func TestMapDNSNormalizesQueryName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"후행 루트 점을 뗀다", "example.com.", "example.com"},
		{"점이 여러 개라도 뗀다", "example.com..", "example.com"},
		{"소문자로 맞춘다", "Example.COM", "example.com"},
		{"둘 다 적용된다", "  API.Example.COM.  ", "api.example.com"},
		{"이미 정규형이면 그대로", "example.com", "example.com"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := MapDNS(etwFactory, etwAt, map[string]string{"QueryName": tc.in}, 1, fakeNamer{})
			if !ok {
				t.Fatal("이벤트가 나오지 않았다")
			}
			if got.Domain != tc.want {
				t.Errorf("domain = %q, want %q", got.Domain, tc.want)
			}
		})
	}
}

// 도메인 없는 DNS 이벤트는 조사에 쓸 데가 없다.
func TestMapDNSDropsEventWithoutQueryName(t *testing.T) {
	for _, props := range []map[string]string{
		{"QueryType": "1", "QueryStatus": "0"},
		{"QueryName": "", "QueryType": "1"},
		{"QueryName": "   ", "QueryType": "1"},
		{"QueryName": ".", "QueryType": "1"},
	} {
		if _, ok := MapDNS(etwFactory, etwAt, props, 1, fakeNamer{1: "a.exe"}); ok {
			t.Errorf("%v 가 통과했다", props)
		}
	}
}

// 역방향 조회는 IP 를 이름으로 되짚는 질의라 "어디에 접속했나" 와 무관한데 양만 많다.
func TestMapDNSDropsReverseLookups(t *testing.T) {
	dropped := []string{
		"7.113.0.203.in-addr.arpa",
		"7.113.0.203.IN-ADDR.ARPA.",
		"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
		"in-addr.arpa",
		"ip6.arpa",
	}
	for _, name := range dropped {
		if _, ok := MapDNS(etwFactory, etwAt, map[string]string{"QueryName": name}, 1, fakeNamer{1: "a.exe"}); ok {
			t.Errorf("%q 가 통과했다", name)
		}
	}

	// 이름만 비슷한 정상 도메인까지 버리면 안 된다.
	kept := []string{"notin-addr.arpa", "example.com", "arpa.example.com"}
	for _, name := range kept {
		if _, ok := MapDNS(etwFactory, etwAt, map[string]string{"QueryName": name}, 1, fakeNamer{1: "a.exe"}); !ok {
			t.Errorf("%q 가 걸러졌다", name)
		}
	}
}

// PID 해석에 실패해도 어떤 도메인을 찾았는지는 남겨야 한다. 프로세스는 곁가지다.
func TestMapDNSKeepsEventWhenPIDUnresolved(t *testing.T) {
	cases := []struct {
		name  string
		pid   int
		namer ProcessNamer
	}{
		{"표에 없는 PID", 999, fakeNamer{}},
		{"헤더에 PID 가 없다", 0, fakeNamer{0: "a.exe"}},
		{"해석기가 없다", 4242, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			props := map[string]string{"QueryName": "example.com", "QueryType": "1"}
			got, ok := MapDNS(etwFactory, etwAt, props, tc.pid, tc.namer)
			if !ok {
				t.Fatal("이벤트가 나오지 않았다")
			}
			if got.Process != "" {
				t.Errorf("process = %q, want 빈 값", got.Process)
			}
			if got.Domain != "example.com" {
				t.Errorf("domain = %q", got.Domain)
			}
		})
	}
}

// 모르는 번호에 이름을 지어 붙이면 조사하는 사람이 그 이름을 믿는다. 숫자 그대로 두는 편이 낫다.
func TestDNSQueryTypeLabel(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"1", "A"},
		{"28", "AAAA"},
		{"5", "CNAME"},
		{"12", "PTR"},
		{"65", "HTTPS"},
		{"255", "ANY"},
		{"99", "99"},     // 표에 없는 번호는 그대로
		{"", ""},         // 속성이 없으면 빈 값
		{"A", "A"},       // 이미 이름으로 오면 그대로
		{"0x1c", "0x1c"}, // 십진수가 아니면 손대지 않는다
	}
	for _, tc := range tests {
		if got := dnsQueryTypeLabel(tc.in); got != tc.want {
			t.Errorf("dnsQueryTypeLabel(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// QueryType 속성이 없으면 detail 에 빈 값을 넣지 않는다.
func TestMapDNSOmitsUnknownDetailFields(t *testing.T) {
	got, ok := MapDNS(etwFactory, etwAt, map[string]string{"QueryName": "example.com"}, 1, fakeNamer{})
	if !ok {
		t.Fatal("이벤트가 나오지 않았다")
	}
	if got.Detail != "" {
		t.Errorf("detail = %q, want 빈 값", got.Detail)
	}
}

// 응답 파싱은 구분자를 확인하지 못한 채로 만들었다. 여러 모양을 다 받아야 한다.
func TestParseDNSAnswers(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"세미콜론", "203.0.113.9;203.0.113.10", []string{"203.0.113.9", "203.0.113.10"}},
		{"세미콜론이 끝에 붙어도 빈 값이 안 생긴다", "203.0.113.9;", []string{"203.0.113.9"}},
		{"쉼표", "203.0.113.9,203.0.113.10", []string{"203.0.113.9", "203.0.113.10"}},
		{"둘이 섞여도 된다", "203.0.113.9;203.0.113.10,203.0.113.11", []string{"203.0.113.9", "203.0.113.10", "203.0.113.11"}},
		{"빈 토큰은 버린다", ";;203.0.113.9;;;203.0.113.10;;", []string{"203.0.113.9", "203.0.113.10"}},
		{"공백만 있는 토큰도 버린다", "203.0.113.9;   ;203.0.113.10", []string{"203.0.113.9", "203.0.113.10"}},
		{"양옆 공백을 턴다", " 203.0.113.9 ; 203.0.113.10 ", []string{"203.0.113.9", "203.0.113.10"}},
		{"레코드 종류 접두어를 뗀다", "type: 5 alias.example.com;type: 1 203.0.113.9", []string{"alias.example.com", "203.0.113.9"}},
		{"접두어에 공백이 없어도 뗀다", "type:5 alias.example.com", []string{"alias.example.com"}},
		{"대소문자가 달라도 뗀다", "TYPE: 1 203.0.113.9", []string{"203.0.113.9"}},
		{"번호만 있고 값이 없으면 버린다", "type: 5;203.0.113.9", []string{"203.0.113.9"}},
		{"IPv6 의 콜론은 구분자가 아니다", "2001:db8::1;2001:db8::2", []string{"2001:db8::1", "2001:db8::2"}},
		{"접두어가 없으면 그대로", "alias.example.com", []string{"alias.example.com"}},
		{"빈 문자열", "", nil},
		{"구분자만", ";;,,", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseDNSAnswers(tc.in); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseDNSAnswers(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// 값의 앞자리를 레코드 번호로 잘못 읽으면 응답 IP 가 조용히 망가진다.
func TestStripDNSResultPrefixKeepsValueThatStartsWithDigits(t *testing.T) {
	if got := stripDNSResultPrefix("93.184.216.34"); got != "93.184.216.34" {
		t.Errorf("got %q", got)
	}
	if got := stripDNSResultPrefix("type:93.184.216.34"); got != "93.184.216.34" {
		t.Errorf("got %q, 번호 뒤에 공백이 없으면 값의 일부다", got)
	}
}

// 실패한 질의도 이벤트로 남는다. 3006 대신 3008 을 고른 근거가 이것이다.
func TestMapDNSKeepsFailedQuery(t *testing.T) {
	props := map[string]string{
		"QueryName":    "nx.example.com.",
		"QueryType":    "28",
		"QueryStatus":  "9003", // DNS_ERROR_RCODE_NAME_ERROR
		"QueryResults": "",
	}
	got, ok := MapDNS(etwFactory, etwAt, props, 4242, fakeNamer{4242: `C:\Windows\System32\nslookup.exe`})
	if !ok {
		t.Fatal("이벤트가 나오지 않았다")
	}
	if got.Domain != "nx.example.com" {
		t.Errorf("domain = %q", got.Domain)
	}
	detail := dnsDetail(t, got)
	if detail["status"] != float64(9003) {
		t.Errorf("detail.status = %v, want 9003", detail["status"])
	}
	if _, has := detail["answers"]; has {
		t.Errorf("응답이 없는데 answers 가 실렸다: %v", detail["answers"])
	}
	if detail["queryType"] != "AAAA" {
		t.Errorf("detail.queryType = %v, want AAAA", detail["queryType"])
	}
}

// 프로바이더 버전에 따라 속성 이름 표기가 흔들려도 DNS 가 조용히 0건이 되면 안 된다.
func TestMapDNSPropIsCaseInsensitive(t *testing.T) {
	props := map[string]string{"queryname": "Example.COM.", "querytype": "1", "queryresults": "203.0.113.9"}
	got, ok := MapDNS(etwFactory, etwAt, props, 1, fakeNamer{1: "a.exe"})
	if !ok {
		t.Fatal("이벤트가 나오지 않았다")
	}
	if got.Domain != "example.com" {
		t.Errorf("domain = %q", got.Domain)
	}
	if detail := dnsDetail(t, got); detail["queryType"] != "A" {
		t.Errorf("detail.queryType = %v", detail["queryType"])
	}
}

func TestPIDCacheReusesResultWithinTTL(t *testing.T) {
	calls := 0
	c := &pidCache{lookup: func(int) string { calls++; return `C:\a.exe` }}

	for i := 0; i < 3; i++ {
		if got := c.Name(42); got != `C:\a.exe` {
			t.Fatalf("Name = %q", got)
		}
	}
	if calls != 1 {
		t.Errorf("조회 %d 회, want 1", calls)
	}
}

// PID 는 재사용된다. 만료 없이 들고 있으면 같은 번호로 새로 뜬 프로세스에 죽은 프로세스의
// 이름을 붙이게 되고, 그건 이름이 없는 것보다 나쁘다.
func TestPIDCacheExpiresSoStalePIDIsNotReused(t *testing.T) {
	now := time.Unix(0, 0)
	path := `C:\old.exe`
	calls := 0
	c := &pidCache{
		lookup: func(int) string { calls++; return path },
		now:    func() time.Time { return now },
	}

	if got := c.Name(42); got != `C:\old.exe` {
		t.Fatalf("Name = %q", got)
	}

	// 만료 직전에는 그대로 쓴다.
	now = now.Add(pidCacheTTL - time.Nanosecond)
	if got := c.Name(42); got != `C:\old.exe` || calls != 1 {
		t.Errorf("만료 전인데 다시 조회했다: got %q, calls %d", got, calls)
	}

	// 만료 뒤에는 다시 조회해서 새 프로세스의 경로를 얻는다.
	now = now.Add(time.Nanosecond)
	path = `C:\new.exe`
	if got := c.Name(42); got != `C:\new.exe` {
		t.Errorf("만료 후 Name = %q, want C:\\new.exe", got)
	}
	if calls != 2 {
		t.Errorf("조회 %d 회, want 2", calls)
	}
}

// 조회 실패도 캐시한다. 죽은 프로세스의 연결이 남아 있는 동안 이벤트마다 다시 조회하지 않는다.
func TestPIDCacheCachesFailure(t *testing.T) {
	calls := 0
	c := &pidCache{lookup: func(int) string { calls++; return "" }}

	for i := 0; i < 3; i++ {
		if got := c.Name(7); got != "" {
			t.Fatalf("Name = %q, want 빈 값", got)
		}
	}
	if calls != 1 {
		t.Errorf("조회 %d 회, want 1", calls)
	}
}

// 오래 도는 에이전트에서 맵이 무한정 커지면 안 된다.
func TestPIDCacheIsBounded(t *testing.T) {
	c := &pidCache{lookup: func(int) string { return "x.exe" }}
	for pid := 1; pid <= pidCacheMax*2+10; pid++ {
		c.Name(pid)
	}
	c.mu.Lock()
	n := len(c.entries)
	c.mu.Unlock()
	if n > pidCacheMax {
		t.Errorf("항목 %d 개, 상한 %d 를 넘었다", n, pidCacheMax)
	}
}

// 프로바이더 버전에 따라 속성 이름 표기가 흔들려도 조용히 0건이 되면 안 된다.
func TestPropIsCaseInsensitiveFallback(t *testing.T) {
	got, ok := MapProcess(etwFactory, etwAt, map[string]string{"imagename": "cmd.exe", "parentprocessid": "7"}, fakeNamer{7: "explorer.exe"})
	if !ok {
		t.Fatal("이벤트가 나오지 않았다")
	}
	if got.Process != "cmd.exe" || got.Parent != "explorer.exe" {
		t.Errorf("got %+v", got)
	}
}

// 서버는 사용자별 시작프로그램 경로를 계정 자리에 * 를 넣어 내려준다.
// 계정 이름을 서버가 알 수 없기 때문이다. 이 * 를 펴지 못하면 사용자별 시작프로그램에
// 파일이 생겨도 잡히지 않는다. 지속성 확보(T1547) 탐지가 통째로 비는 자리다.
func TestUnderWatchPathsExpandsSegmentWildcard(t *testing.T) {
	watch := []string{
		`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`,
		`C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`,
	}

	cases := map[string]bool{
		`C:\Users\dhkim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\evil.lnk`: true,
		`C:\Users\admin\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.exe`:    true,
		// 와일드카드는 한 단계만 먹는다. 두 단계를 건너뛰면 안 된다.
		`C:\Users\a\b\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.exe`: false,
		// 와일드카드 뒤가 다르면 안 걸린다.
		`C:\Users\dhkim\Documents\x.exe`: false,
		// 와일드카드 없는 경로는 그대로 동작해야 한다.
		`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\ok.lnk`: true,
		`C:\Windows\System32\notepad.exe`:                                     false,
	}
	for path, want := range cases {
		if got := underWatchPaths(path, watch); got != want {
			t.Errorf("underWatchPaths(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestUnderWatchPathsWildcardOnDevicePath(t *testing.T) {
	// ETW 는 장치 경로로 준다. 정규화 뒤에도 와일드카드가 먹어야 한다.
	watch := []string{`C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`}
	device := `\Device\HarddiskVolume3\Users\dhkim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\evil.lnk`

	if !underWatchPaths(device, watch) {
		t.Errorf("장치 경로에서 와일드카드가 안 먹었다: %q", device)
	}
}

// ETW 세션 생성 실패는 원인이 둘로 갈리는데 조치가 정반대다.
// 실기기에 접근할 수 없는 상태에서는 이 구분이 원인 파악의 거의 전부다.
func TestSessionErrorHint(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"권한 없음", syscall.Errno(5), "관리자 권한"},
		{"고아 세션", syscall.Errno(183), "logman stop"},
		{"감싼 오류도 푼다", fmt.Errorf("StartTrace: %w", syscall.Errno(183)), "logman stop"},
		{"모르는 오류", errors.New("무언가 잘못됨"), "관리자 권한"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sessionErrorHint(tc.err, "EDRdog-Agent"); !strings.Contains(got, tc.want) {
				t.Errorf("sessionErrorHint(%v) = %q, %q 를 담아야 한다", tc.err, got, tc.want)
			}
		})
	}
}
