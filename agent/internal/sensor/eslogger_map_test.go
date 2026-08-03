package sensor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/event"
)

var eslFactory = event.Factory{Host: "lab-mac"}

// eslExecLine 은 eslogger exec 출력 한 줄을 만든다.
// 필드 구성은 실제 출력을 따랐고, 판정에 쓰이지 않는 stat/env/fds 는 뺐다.
func eslExecLine(parentPath, targetPath, argsJSON string) string {
	return `{"schema_version":1,"mach_time":518281374289,"event_type":9,` +
		`"time":"2026-07-30T04:15:22.123456Z","version":8,"seq_num":1204,` +
		`"thread":{"thread_id":2201},` +
		`"process":{"ppid":1,"original_ppid":1,"group_id":501,"session_id":501,` +
		`"is_platform_binary":true,"is_es_client":false,` +
		`"signing_id":"com.apple.zsh","team_id":null,` +
		`"audit_token":{"pid":501,"euid":0,"ruid":0,"egid":0,"rgid":0,"auid":501,"asid":100,"pidversion":40},` +
		`"parent_audit_token":{"pid":1},` +
		`"executable":{"path":"` + parentPath + `","path_truncated":false,"stat":{"st_ino":1234,"st_uid":0}}},` +
		`"event":{"exec":{"image_cputype":16777228,"image_cpusubtype":0,"last_fd":3,"script":null,` +
		`"args":` + argsJSON + `,"env":["PATH=/usr/bin"],` +
		`"cwd":{"path":"/Users/lab","path_truncated":false},` +
		`"fds":[{"fd":0,"fdtype":1}],` +
		`"target":{"ppid":501,"original_ppid":501,"group_id":501,"session_id":501,` +
		`"is_platform_binary":true,"is_es_client":false,"signing_id":"com.apple.sh","team_id":null,` +
		`"audit_token":{"pid":4242,"euid":0,"ruid":0,"egid":0,"rgid":0,"auid":501,"asid":100,"pidversion":41},` +
		`"parent_audit_token":{"pid":501},` +
		`"executable":{"path":"` + targetPath + `","path_truncated":false,"stat":{"st_ino":5678,"st_uid":0}}}}}}`
}

func TestMapLineExecMakesProcessEvent(t *testing.T) {
	line := eslExecLine("/bin/zsh", "/usr/bin/curl", `["curl","-fsSL","https://example.test/x"]`)

	e, ok := MapLine(eslFactory, []byte(line), nil, nil)
	if !ok {
		t.Fatal("exec 줄을 이벤트로 바꾸지 못했다")
	}
	if e.Type != event.TypeProcess {
		t.Errorf("Type = %q, want %q", e.Type, event.TypeProcess)
	}
	if e.Host != "lab-mac" {
		t.Errorf("Host = %q, want lab-mac", e.Host)
	}
	if e.Process != "curl" {
		t.Errorf("Process = %q, want curl", e.Process)
	}
	if e.Parent != "zsh" {
		t.Errorf("Parent = %q, want zsh", e.Parent)
	}
	want := "/usr/bin/curl -fsSL https://example.test/x"
	if e.Cmdline != want {
		t.Errorf("Cmdline = %q, want %q", e.Cmdline, want)
	}

	at, err := time.Parse(time.RFC3339Nano, "2026-07-30T04:15:22.123456Z")
	if err != nil {
		t.Fatal(err)
	}
	if e.TS != at.UnixMilli() {
		t.Errorf("TS = %d, want %d", e.TS, at.UnixMilli())
	}
}

func TestMapLineExecInterpreterMakesScriptEvent(t *testing.T) {
	cases := []struct {
		path string
		name string
	}{
		{"/bin/sh", "sh"},
		{"/bin/bash", "bash"},
		{"/bin/zsh", "zsh"},
		{"/usr/bin/python3", "python3"},
		{"/opt/homebrew/bin/python3.12", "python3.12"},
		{"/usr/bin/osascript", "osascript"},
		{"/usr/bin/perl", "perl"},
		{"/usr/bin/ruby", "ruby"},
		// node 가 빠져 있으면 node /tmp/evil.js 를 아무 룰도 못 본다.
		// process 로 오면 R2 는 argv[0] 가 node 라서, R3 는 script 가 아니라서 지나친다.
		{"/opt/homebrew/bin/node", "node"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			line := eslExecLine("/usr/libexec/launchd", c.path, `["`+c.name+`","-c","whoami"]`)

			e, ok := MapLine(eslFactory, []byte(line), nil, nil)
			if !ok {
				t.Fatal("이벤트로 바꾸지 못했다")
			}
			if e.Type != event.TypeScript {
				t.Errorf("Type = %q, want %q", e.Type, event.TypeScript)
			}
			if e.Process != c.name {
				t.Errorf("Process = %q, want %q", e.Process, c.name)
			}
			if e.Parent != "launchd" {
				t.Errorf("Parent = %q, want launchd", e.Parent)
			}
		})
	}
}

// detector 의 R2 룰은 cmdline 첫 토큰에서 /tmp/ 같은 표식을 찾는다.
// argv[0] 를 eslogger 가 준 값 그대로 두면 파일명만 남아 룰이 발화하지 않는다.
func TestMapLineExecPutsFullPathInArgv0(t *testing.T) {
	line := eslExecLine("/bin/bash", "/tmp/evil.sh", `["evil.sh","--quiet"]`)

	e, ok := MapLine(eslFactory, []byte(line), nil, nil)
	if !ok {
		t.Fatal("이벤트로 바꾸지 못했다")
	}
	if got := strings.Fields(e.Cmdline)[0]; got != "/tmp/evil.sh" {
		t.Errorf("argv0 = %q, want /tmp/evil.sh", got)
	}
	if e.Cmdline != "/tmp/evil.sh --quiet" {
		t.Errorf("Cmdline = %q", e.Cmdline)
	}
}

func TestMapLineExecWithoutArgsUsesExecutablePath(t *testing.T) {
	line := eslExecLine("/bin/zsh", "/usr/bin/whoami", `[]`)

	e, ok := MapLine(eslFactory, []byte(line), nil, nil)
	if !ok {
		t.Fatal("이벤트로 바꾸지 못했다")
	}
	if e.Cmdline != "/usr/bin/whoami" {
		t.Errorf("Cmdline = %q, want /usr/bin/whoami", e.Cmdline)
	}
}

func TestMapLineExecRedactsSecrets(t *testing.T) {
	args := `["curl","--password","hunter2","--api-key=abcd1234","-u","lab","--token","t0k3n","--secret_key=zzz"]`
	line := eslExecLine("/bin/zsh", "/usr/bin/curl", args)

	e, ok := MapLine(eslFactory, []byte(line), nil, nil)
	if !ok {
		t.Fatal("이벤트로 바꾸지 못했다")
	}
	want := "/usr/bin/curl --password <redacted> --api-key=<redacted> -u lab --token <redacted> --secret_key=<redacted>"
	if e.Cmdline != want {
		t.Errorf("Cmdline = %q,\n want %q", e.Cmdline, want)
	}
}

// 비밀값 자리에 또 플래그처럼 생긴 값이 와도 그 다음 인자까지 가리면 안 된다.
func TestMapLineExecRedactionDoesNotCascade(t *testing.T) {
	line := eslExecLine("/bin/zsh", "/usr/bin/tool", `["tool","--token","--verbose","--quiet"]`)

	e, ok := MapLine(eslFactory, []byte(line), nil, nil)
	if !ok {
		t.Fatal("이벤트로 바꾸지 못했다")
	}
	want := "/usr/bin/tool --token <redacted> --quiet"
	if e.Cmdline != want {
		t.Errorf("Cmdline = %q, want %q", e.Cmdline, want)
	}
}

func eslCreateLine(dir, filename string) string {
	return `{"schema_version":1,"event_type":13,"time":"2026-07-30T04:15:22Z",` +
		`"process":{"executable":{"path":"/bin/cp"},"audit_token":{"pid":900}},` +
		`"event":{"create":{"destination_type":1,"destination":{"new_path":{` +
		`"dir":{"path":"` + dir + `","path_truncated":false},"filename":"` + filename + `","mode":33188}}}}}`
}

func eslUnlinkLine(target string) string {
	return `{"schema_version":1,"event_type":14,"time":"2026-07-30T04:15:22Z",` +
		`"process":{"executable":{"path":"/bin/rm"},"audit_token":{"pid":901}},` +
		`"event":{"unlink":{"target":{"path":"` + target + `","path_truncated":false},` +
		`"parent_dir":{"path":"/Library/LaunchDaemons"}}}}`
}

func eslRenameLine(source, destDir, destName string) string {
	return `{"schema_version":1,"event_type":25,"time":"2026-07-30T04:15:22Z",` +
		`"process":{"executable":{"path":"/bin/mv"},"audit_token":{"pid":902}},` +
		`"event":{"rename":{"source":{"path":"` + source + `","path_truncated":false},` +
		`"destination_type":1,"destination":{"new_path":{` +
		`"dir":{"path":"` + destDir + `"},"filename":"` + destName + `"}}}}}`
}

func TestMapLineFileEventsInsideWatchPaths(t *testing.T) {
	watch := []string{"/Library/LaunchAgents", "/Library/LaunchDaemons"}

	cases := []struct {
		name    string
		line    string
		wantPr  string
		wantCmd string
	}{
		{
			name:    "create",
			line:    eslCreateLine("/Library/LaunchAgents", "com.evil.plist"),
			wantPr:  "com.evil.plist",
			wantCmd: "/Library/LaunchAgents/com.evil.plist",
		},
		{
			name:    "unlink",
			line:    eslUnlinkLine("/Library/LaunchDaemons/com.gone.plist"),
			wantPr:  "com.gone.plist",
			wantCmd: "/Library/LaunchDaemons/com.gone.plist",
		},
		{
			name:    "rename 목적지가 감시 대상",
			line:    eslRenameLine("/tmp/staged.plist", "/Library/LaunchAgents", "com.moved.plist"),
			wantPr:  "com.moved.plist",
			wantCmd: "/Library/LaunchAgents/com.moved.plist",
		},
		{
			name:    "rename 원본이 감시 대상",
			line:    eslRenameLine("/Library/LaunchAgents/com.old.plist", "/tmp", "stash.plist"),
			wantPr:  "com.old.plist",
			wantCmd: "/Library/LaunchAgents/com.old.plist",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, ok := MapLine(eslFactory, []byte(c.line), watch, nil)
			if !ok {
				t.Fatal("이벤트로 바꾸지 못했다")
			}
			if e.Type != event.TypeFile {
				t.Errorf("Type = %q, want %q", e.Type, event.TypeFile)
			}
			if e.Process != c.wantPr {
				t.Errorf("Process = %q, want %q", e.Process, c.wantPr)
			}
			// detector 의 T1547 룰이 전체 경로에서 자동실행 표식을 찾는다.
			if e.Cmdline != c.wantCmd {
				t.Errorf("Cmdline = %q, want %q", e.Cmdline, c.wantCmd)
			}
		})
	}
}

// pid 와 ppid 는 둘 다 target 에서 나와야 한다. 우리가 보고하는 프로세스가 target 이다.
func TestMapLineExecCarriesIdentifiers(t *testing.T) {
	line := eslExecLine("/bin/zsh", "/usr/bin/curl", `["curl","-fsSL","https://example.test/x"]`)

	e, ok := MapLine(eslFactory, []byte(line), nil, nil)
	if !ok {
		t.Fatal("이벤트로 바꾸지 못했다")
	}
	// eslExecLine 의 target 은 audit_token.pid 4242, ppid 501 이다.
	if e.Detail != `{"pid":4242,"ppid":501}` {
		t.Errorf("Detail = %q, want pid 4242 / ppid 501", e.Detail)
	}
}

// exec 시점의 이미지는 커널이 이미 읽어 올린 파일이라 완성돼 있다. 그때만 해시를 붙인다.
func TestMapLineExecCarriesSHA256(t *testing.T) {
	content := []byte("#!/bin/sh\necho hi\n")
	path := writeFile(t, "tool", content)
	line := eslExecLine("/bin/zsh", path, `["tool"]`)

	e, ok := MapLine(eslFactory, []byte(line), nil, NewFileHasher())
	if !ok {
		t.Fatal("이벤트로 바꾸지 못했다")
	}
	if e.SHA256 != wantSHA(content) {
		t.Errorf("SHA256 = %q, want %q", e.SHA256, wantSHA(content))
	}

	// 해시기를 안 주면 그 자리만 빈다. 이벤트는 그대로 나가야 한다.
	e, ok = MapLine(eslFactory, []byte(line), nil, nil)
	if !ok || e.SHA256 != "" {
		t.Errorf("해시기 없이 만든 이벤트 = %+v", e)
	}
}

func TestMapLineFileEventsCarryAction(t *testing.T) {
	watch := []string{"/Library/LaunchAgents", "/Library/LaunchDaemons"}

	cases := map[string]struct {
		line       string
		wantAction string
	}{
		"create": {eslCreateLine("/Library/LaunchAgents", "com.evil.plist"), event.FileActionCreate},
		"rename": {eslRenameLine("/tmp/staged.plist", "/Library/LaunchAgents", "com.moved.plist"), event.FileActionRename},
		"unlink": {eslUnlinkLine("/Library/LaunchDaemons/com.gone.plist"), event.FileActionDelete},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e, ok := MapLine(eslFactory, []byte(c.line), watch, NewFileHasher())
			if !ok {
				t.Fatal("이벤트로 바꾸지 못했다")
			}
			want := `{"action":"` + c.wantAction + `"}`
			if e.Detail != want {
				t.Errorf("Detail = %q, want %q", e.Detail, want)
			}
			// 파일 이벤트에는 해시를 붙이지 않는다. 그 시점의 파일은 아직 다 안 쓰였을 수 있고,
			// 부분 내용의 해시는 없는 것보다 나쁘다(eslFileEvent 주석).
			if e.SHA256 != "" {
				t.Errorf("SHA256 = %q, 파일 이벤트에는 붙이지 않는다", e.SHA256)
			}
		})
	}
}

// 실제로 존재하는 파일이어도 파일 이벤트면 해시를 뜨지 않는다.
// 부분 기록 문제 때문에 내린 판단이라 "읽을 수 있으면 붙인다" 로 미끄러지지 않아야 한다.
func TestMapLineFileEventNeverHashesExistingFile(t *testing.T) {
	path := writeFile(t, "com.evil.plist", []byte("<plist/>"))
	dir, name := filepath.Split(path)
	line := eslCreateLine(strings.TrimSuffix(dir, "/"), name)

	e, ok := MapLine(eslFactory, []byte(line), []string{strings.TrimSuffix(dir, "/")}, NewFileHasher())
	if !ok {
		t.Fatal("이벤트로 바꾸지 못했다")
	}
	if e.SHA256 != "" {
		t.Errorf("SHA256 = %q, 파일 이벤트에는 붙이지 않는다", e.SHA256)
	}
}

func TestMapLineFileEventsOutsideWatchPathsAreDropped(t *testing.T) {
	watch := []string{"/Library/LaunchAgents"}

	cases := []struct {
		name string
		line string
	}{
		{"감시 대상 밖", eslCreateLine("/Users/lab/Downloads", "note.txt")},
		{"이름만 겹치는 형제 디렉터리", eslCreateLine("/Library/LaunchAgentsBackup", "com.evil.plist")},
		{"감시 경로가 비었을 때", eslUnlinkLine("/Library/LaunchAgents/com.evil.plist")},
	}

	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := watch
			if i == 2 {
				w = nil
			}
			if _, ok := MapLine(eslFactory, []byte(c.line), w, nil); ok {
				t.Error("감시 대상이 아닌데 이벤트가 나왔다")
			}
		})
	}
}

// destination 공용체는 destination_type 에 따라 existing_file 쪽이 채워지기도 한다.
func TestMapLineCreateWithExistingFileDestination(t *testing.T) {
	line := `{"schema_version":1,"event_type":13,"time":"2026-07-30T04:15:22Z",` +
		`"process":{"executable":{"path":"/bin/cp"}},` +
		`"event":{"create":{"destination_type":0,"destination":{"existing_file":` +
		`{"path":"/Library/LaunchAgents/com.exists.plist","path_truncated":false}}}}}`

	e, ok := MapLine(eslFactory, []byte(line), []string{"/Library/LaunchAgents"}, nil)
	if !ok {
		t.Fatal("이벤트로 바꾸지 못했다")
	}
	if e.Cmdline != "/Library/LaunchAgents/com.exists.plist" {
		t.Errorf("Cmdline = %q", e.Cmdline)
	}
}

func TestMapLineRejectsBadInput(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{"빈 줄", ``},
		{"잘린 JSON", `{"event":{"exec":{"args":["sh"`},
		{"JSON 이 아님", `Failed to create ES client: Not privileged`},
		{"구독하지 않은 이벤트", `{"schema_version":1,"event_type":10,"time":"2026-07-30T04:15:22Z","event":{"open":{"fflag":1,"file":{"path":"/etc/passwd"}}}}`},
		{"event 가 없음", `{"schema_version":1,"event_type":9,"time":"2026-07-30T04:15:22Z"}`},
		{"exec 인데 실행 경로가 없음", `{"schema_version":1,"event":{"exec":{"args":["sh"],"target":{"executable":{"path":""}}}}}`},
		{"JSON 배열", `[1,2,3]`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, ok := MapLine(eslFactory, []byte(c.line), []string{"/Library/LaunchAgents"}, nil); ok {
				t.Error("이벤트가 나오면 안 된다")
			}
		})
	}
}

// 시각이 없거나 형식이 어긋나도 실행 사실 자체는 올려야 한다.
func TestMapLineWithoutTimeStillEmits(t *testing.T) {
	line := `{"schema_version":1,"process":{"executable":{"path":"/bin/zsh"}},` +
		`"event":{"exec":{"args":["ls"],"target":{"executable":{"path":"/bin/ls"}}}}}`

	before := time.Now().UnixMilli()
	e, ok := MapLine(eslFactory, []byte(line), nil, nil)
	if !ok {
		t.Fatal("이벤트로 바꾸지 못했다")
	}
	if e.TS < before {
		t.Errorf("TS = %d, 현재 시각으로 채워져야 한다", e.TS)
	}
}

func TestExpandHome(t *testing.T) {
	cases := []struct {
		in   string
		home string
		want string
	}{
		{"~/Library/LaunchAgents", "/Users/lab", "/Users/lab/Library/LaunchAgents"},
		{"~", "/Users/lab", "/Users/lab"},
		{"/Library/LaunchDaemons", "/Users/lab", "/Library/LaunchDaemons"},
		{"~other/Library", "/Users/lab", "~other/Library"},
		{"~/Library", "", "~/Library"},
	}
	for _, c := range cases {
		if got := eslExpandHome(c.in, c.home); got != c.want {
			t.Errorf("eslExpandHome(%q, %q) = %q, want %q", c.in, c.home, got, c.want)
		}
	}
}

func TestExpandWatchPathsUsesRealHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("홈 디렉터리를 알 수 없다")
	}
	got := ExpandWatchPaths([]string{"~/Library/LaunchAgents", "/Library/LaunchDaemons"})
	want := []string{home + "/Library/LaunchAgents", "/Library/LaunchDaemons"}
	if len(got) != len(want) {
		t.Fatalf("길이 = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// 확장한 경로로 실제 파일 이벤트가 걸리는지까지 본다. 확장만 되고 필터가 안 맞으면 의미가 없다.
func TestMapLineFileEventUnderExpandedHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("홈 디렉터리를 알 수 없다")
	}
	watch := ExpandWatchPaths([]string{"~/Library/LaunchAgents"})
	line := eslCreateLine(home+"/Library/LaunchAgents", "com.user.plist")

	e, ok := MapLine(eslFactory, []byte(line), watch, nil)
	if !ok {
		t.Fatal("확장한 감시 경로에 걸리지 않았다")
	}
	if e.Cmdline != home+"/Library/LaunchAgents/com.user.plist" {
		t.Errorf("Cmdline = %q", e.Cmdline)
	}
}

func TestEslUnderWatchIgnoresTrailingSlash(t *testing.T) {
	if !eslUnderWatch("/Library/LaunchAgents/x.plist", []string{"/Library/LaunchAgents/"}) {
		t.Error("끝에 슬래시가 붙은 감시 경로가 안 맞았다")
	}
	if eslUnderWatch("", []string{"/Library/LaunchAgents"}) {
		t.Error("빈 경로가 맞으면 안 된다")
	}
}
