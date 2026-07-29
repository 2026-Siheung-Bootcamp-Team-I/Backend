package sensor

import (
	"encoding/json"
	"os"
	"path"
	"strings"
	"time"

	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/event"
)

// eslogger 가 내는 JSON 은 es_message_t 를 그대로 옮긴 모양이다(eslogger(1)).
// 필요한 가지만 골라 담는다. 나머지 필드(stat, fds, env ...)는 무시한다.
//
// 이벤트 종류는 event 객체의 멤버 이름으로 구분한다. 최상위 event_type 숫자를 쓰면
// 매크로 값과 코드가 따로 놀아 나중에 맞추기 어렵다.
type eslLine struct {
	Time    json.RawMessage `json:"time"`
	Process eslProcess      `json:"process"`
	Event   struct {
		Exec   *eslExec   `json:"exec"`
		Create *eslCreate `json:"create"`
		Rename *eslRename `json:"rename"`
		Unlink *eslUnlink `json:"unlink"`
	} `json:"event"`
}

// eslProcess 는 es_process_t 다. 실행 파일 경로만 쓴다.
type eslProcess struct {
	Executable eslFile `json:"executable"`
}

// eslFile 은 es_file_t 다.
type eslFile struct {
	Path string `json:"path"`
}

// eslExec 은 es_event_exec_t 다.
// target 은 이미지가 바뀐 뒤의 프로세스이고, 바깥 message.process 는 exec 를 호출한 쪽,
// 즉 우리가 부모로 쓸 프로세스다.
type eslExec struct {
	Args   []string   `json:"args"`
	Target eslProcess `json:"target"`
}

// eslDestination 은 es_event_create_t / es_event_rename_t 의 destination 공용체다.
// destination_type 에 따라 둘 중 하나만 채워진다.
type eslDestination struct {
	ExistingFile *eslFile `json:"existing_file"`
	NewPath      *struct {
		Dir      eslFile `json:"dir"`
		Filename string  `json:"filename"`
	} `json:"new_path"`
}

type eslCreate struct {
	Destination eslDestination `json:"destination"`
}

type eslRename struct {
	Source      eslFile        `json:"source"`
	Destination eslDestination `json:"destination"`
}

type eslUnlink struct {
	Target eslFile `json:"target"`
}

// eslRedacted 는 가려진 값을 대신하는 표시다.
const eslRedacted = "<redacted>"

// eslInterpreters 는 script 이벤트로 올릴 인터프리터다. detector 가 script 에만 T1059 룰을 건다.
var eslInterpreters = map[string]bool{
	"sh":        true,
	"bash":      true,
	"zsh":       true,
	"osascript": true,
	"perl":      true,
	"ruby":      true,
}

// eslSecretNames 는 이 조각이 들어간 플래그의 값을 가린다.
// 대시와 밑줄을 지우고 소문자로 맞춘 뒤 비교하므로 --api-key, --API_KEY, --apikey 가 모두 걸린다.
var eslSecretNames = []string{"password", "passwd", "token", "secret", "apikey", "accesskey", "credential"}

// MapLine 은 eslogger 가 낸 JSON 한 줄을 이벤트로 바꾼다.
//
// 바꿀 수 없는 줄(깨진 JSON, 구독하지 않은 종류, watchPaths 밖의 파일)은 false 를 돌려준다.
// 한 줄이 이상하다고 센서가 멈추면 안 되므로 여기서는 어떤 입력에도 panic 하지 않는다.
func MapLine(f event.Factory, line []byte, watchPaths []string) (event.Event, bool) {
	var l eslLine
	if err := json.Unmarshal(line, &l); err != nil {
		return event.Event{}, false
	}
	at := l.at()

	switch {
	case l.Event.Exec != nil:
		return eslExecEvent(f, at, l)
	case l.Event.Create != nil:
		return eslFileEvent(f, at, watchPaths, l.Event.Create.Destination.paths())
	case l.Event.Rename != nil:
		// 감시 경로로 옮겨 오는 쪽이 주된 관심사이므로 목적지를 먼저 본다.
		// 감시 경로 밖으로 빠져나간 경우도 놓치지 않도록 원본을 뒤에 둔다.
		r := l.Event.Rename
		return eslFileEvent(f, at, watchPaths, append(r.Destination.paths(), r.Source.Path))
	case l.Event.Unlink != nil:
		return eslFileEvent(f, at, watchPaths, []string{l.Event.Unlink.Target.Path})
	}
	return event.Event{}, false
}

// eslExecEvent 는 exec 이벤트를 process 또는 script 이벤트로 만든다.
func eslExecEvent(f event.Factory, at time.Time, l eslLine) (event.Event, bool) {
	execPath := l.Event.Exec.Target.Executable.Path
	if execPath == "" {
		return event.Event{}, false
	}
	cmdline := eslCmdline(execPath, l.Event.Exec.Args)
	parent := eslBase(l.Process.Executable.Path)

	if eslIsInterpreter(eslBase(execPath)) {
		return f.Script(at, execPath, cmdline, parent), true
	}
	return f.Process(at, execPath, cmdline, parent), true
}

// eslFileEvent 는 후보 경로 중 감시 대상에 드는 첫 번째 것으로 파일 이벤트를 만든다.
//
// 감시 경로로 거르는 이유는 양이다. create/rename/unlink 는 평범한 맥에서 초당 수백 건이 나오고
// 그걸 다 올리면 서버가 감당하지 못한다.
func eslFileEvent(f event.Factory, at time.Time, watchPaths, candidates []string) (event.Event, bool) {
	for _, p := range candidates {
		if eslUnderWatch(p, watchPaths) {
			return f.File(at, p), true
		}
	}
	return event.Event{}, false
}

// paths 는 destination 공용체에서 대상 경로를 뽑는다. 채워진 쪽만 값이 나온다.
func (d eslDestination) paths() []string {
	var out []string
	if d.ExistingFile != nil && d.ExistingFile.Path != "" {
		out = append(out, d.ExistingFile.Path)
	}
	if d.NewPath != nil && d.NewPath.Dir.Path != "" && d.NewPath.Filename != "" {
		out = append(out, path.Join(d.NewPath.Dir.Path, d.NewPath.Filename))
	}
	return out
}

// at 은 이벤트 시각을 돌려준다.
// eslogger 는 RFC3339 문자열을 주지만, 형식이 어긋나도 이벤트를 버리지 않고 현재 시각을 쓴다.
// 시각 하나 때문에 실행 사실 자체를 놓치는 쪽이 더 나쁘다.
func (l eslLine) at() time.Time {
	var s string
	if err := json.Unmarshal(l.Time, &s); err == nil {
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			return t
		}
	}
	return time.Now()
}

// eslCmdline 은 인자 배열을 명령행 한 줄로 잇는다.
//
// argv[0] 는 eslogger 가 준 값 대신 실행 파일 전체 경로로 바꾼다.
// detector 의 R2 룰이 cmdline 의 첫 토큰에서 /tmp/ 같은 표식을 찾는데, argv[0] 는 보통
// 파일명만 담고 있어 그대로 두면 CRITICAL 룰이 발화하지 않는다.
func eslCmdline(execPath string, args []string) string {
	argv := eslRedactArgs(args)
	if len(argv) == 0 {
		return execPath
	}
	argv[0] = execPath
	return strings.Join(argv, " ")
}

// eslRedactArgs 는 비밀값으로 보이는 인자를 가린 새 배열을 돌려준다.
// --password 값 과 --password=값 두 형태를 모두 다룬다. argv[0] 는 실행 경로이므로 건드리지 않는다.
func eslRedactArgs(args []string) []string {
	argv := make([]string, len(args))
	copy(argv, args)

	for i := 1; i < len(argv); i++ {
		tok := argv[i]
		if !strings.HasPrefix(tok, "-") {
			continue
		}
		if eq := strings.IndexByte(tok, '='); eq >= 0 {
			if eslIsSecretFlag(tok[:eq]) {
				argv[i] = tok[:eq+1] + eslRedacted
			}
			continue
		}
		if eslIsSecretFlag(tok) && i+1 < len(argv) {
			argv[i+1] = eslRedacted
			i++ // 가린 값을 다시 플래그로 보지 않는다
		}
	}
	return argv
}

// eslIsSecretFlag 는 플래그 이름이 비밀값을 받는 것인지 본다.
func eslIsSecretFlag(flag string) bool {
	name := strings.TrimLeft(flag, "-")
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "-", "")
	name = strings.ReplaceAll(name, "_", "")
	if name == "" {
		return false
	}
	for _, s := range eslSecretNames {
		if strings.Contains(name, s) {
			return true
		}
	}
	return false
}

// eslIsInterpreter 는 실행 파일명이 스크립트 인터프리터인지 본다.
// python 은 python3, python3.12 처럼 판이 이름에 붙으므로 앞부분만 본다.
func eslIsInterpreter(name string) bool {
	return eslInterpreters[name] || strings.HasPrefix(name, "python")
}

// eslUnderWatch 는 경로가 감시 대상 아래에 있는지 본다.
// 단순 접두사 비교는 /Library/LaunchAgents 로 /Library/LaunchAgentsBackup 까지 잡으므로
// 경로 경계까지 맞춘다.
func eslUnderWatch(p string, watchPaths []string) bool {
	if p == "" {
		return false
	}
	for _, w := range watchPaths {
		w = strings.TrimSuffix(w, "/")
		if w == "" {
			continue
		}
		if p == w || strings.HasPrefix(p, w+"/") {
			return true
		}
	}
	return false
}

// ExpandWatchPaths 는 서버가 내려준 감시 경로의 ~ 를 실제 홈 디렉터리로 바꾼다.
// 서버는 ~/Library/LaunchAgents 처럼 내려주는데 커널이 주는 경로는 언제나 절대 경로라
// 펴 두지 않으면 어떤 파일 이벤트도 걸리지 않는다.
func ExpandWatchPaths(paths []string) []string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = ""
	}
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		out = append(out, eslExpandHome(p, home))
	}
	return out
}

// eslExpandHome 은 ~ 로 시작하는 경로 하나를 편다.
// home 을 알 수 없거나 ~user 형태면 손대지 않는다. 잘못 편 경로보다 안 편 경로가 낫다.
func eslExpandHome(p, home string) string {
	if home == "" || !strings.HasPrefix(p, "~") {
		return p
	}
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") {
		return path.Join(home, p[2:])
	}
	return p
}

// eslBase 는 경로에서 파일명만 남긴다.
// event 패키지에도 같은 일을 하는 것이 있지만 그쪽은 이벤트를 만들 때만 쓰이고,
// 여기서는 부모 이름과 인터프리터 판별에 미리 필요하다.
func eslBase(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}
