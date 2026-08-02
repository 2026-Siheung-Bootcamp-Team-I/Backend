package sensor

import (
	"strconv"
	"strings"
	"time"

	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/event"
)

// ETW 이벤트를 판정에 쓰는 이벤트로 바꾼다. 속성 맵만 받는 순수 함수라 빌드 태그 없이 둔다.
// etw_windows.go 는 콜백에서 속성을 꺼내 이 함수들에 넘기는 배선만 한다.

// ETW 속성 이름. 매니페스트 정의와 같아야 한다.
const (
	propImageName       = "ImageName"
	propProcessID       = "ProcessID"
	propParentProcessID = "ParentProcessID"
	propPID             = "PID"
	propDestAddr        = "daddr"
	propDestPort        = "dport"
	propSrcPort         = "sport"
	propFileName        = "FileName"
	propQueryName       = "QueryName"
	propQueryType       = "QueryType"
	propQueryStatus     = "QueryStatus"
	propQueryResults    = "QueryResults"

	// 아래 둘은 매니페스트에 없다. 배선(etw_windows.go)이 프로세스를 조회해 같은 맵에 채워 넣는다.
	propImagePath   = "ImagePath"
	propCommandLine = "CommandLine"
)

// MapProcess 는 ProcessStart 속성 맵을 프로세스 또는 스크립트 이벤트로 바꾼다.
// 배선이 채운 ImagePath 가 없으면 파일명뿐인 ImageName 으로 물러나되 이벤트는 내보낸다.
// hasher 는 실행 이미지의 sha256 을 구한다. nil 이면 해시를 붙이지 않는다.
func MapProcess(f event.Factory, at time.Time, props map[string]string, namer ProcessNamer, hasher *FileHasher) (event.Event, bool) {
	// 전체 경로가 먼저다. 파일명만 넘기면 R2/R3 룰이 찾는 \temp\ 같은 표식이 사라진다.
	exe := prop(props, propImagePath)
	if exe == "" {
		exe = prop(props, propImageName)
	}
	if exe == "" {
		return event.Event{}, false
	}

	cmdline := prop(props, propCommandLine)
	switch {
	case cmdline != "":
		cmdline = withArgv0(cmdline, exe)
	case hasPathSeparator(exe):
		// 명령행을 못 읽었어도 전체 경로를 알면 그것만이라도 담는다.
		cmdline = exe
	}
	// 둘 다 없으면 빈 채로 둔다. 파일명을 채워 넣으면 responder 의 조치 대상이 이름으로 흐려진다.
	cmdline = redactSecrets(cmdline)

	ppid, _ := parsePID(prop(props, propParentProcessID))
	parent := ""
	if ppid > 0 && namer != nil {
		parent = baseName(namer.Name(ppid))
	}
	pid, _ := parsePID(prop(props, propProcessID))

	info := event.ProcessInfo{
		Path:    exe,
		Cmdline: cmdline,
		Parent:  parent,
		PID:     pid,
		PPID:    ppid,
		// 전체 경로일 때만 해시를 뜬다. 파일명만으로 열면 상대 경로가 돼 엉뚱한 파일 해시가 붙는다.
		SHA256: hashFullPath(hasher, exe),
	}
	// 인터프리터는 script 로 낸다. detector 가 script 타입에만 T1059 룰을 건다.
	if isInterpreter(exe) {
		return f.Script(at, info), true
	}
	return f.Process(at, info), true
}

// hashFullPath 는 전체 경로일 때만 해시를 구한다. 파일명만 아는 값은 열지 않는다.
func hashFullPath(hasher *FileHasher, path string) string {
	if !hasPathSeparator(path) {
		return ""
	}
	return hasher.Hash(path)
}

// MapNetwork 는 TCP 연결시도 속성 맵을 네트워크 이벤트로 바꾼다.
// PID 해석에 실패해도 목적지 IP 기반 판정이 남으므로 프로세스명 없이 내보낸다.
func MapNetwork(f event.Factory, at time.Time, props map[string]string, namer ProcessNamer) (event.Event, bool) {
	dest := prop(props, propDestAddr)
	// IsPublic 을 그대로 쓴다. 따로 만들면 같은 목적지를 플랫폼마다 다르게 거르게 된다.
	if !IsPublic(dest) {
		return event.Event{}, false
	}

	pid, _ := parsePID(prop(props, propPID))
	path := ""
	if pid > 0 && namer != nil {
		path = namer.Name(pid)
	}

	// ntohs 를 넣지 마라. TDH 가 렌더링해 준 값이라 한 번 더 뒤집으면 443 이 47873 이 된다.
	port, _ := strconv.Atoi(strings.TrimSpace(prop(props, propDestPort)))
	if port < 0 || port > 65535 {
		port = 0
	}
	// 프로토콜은 tcp 로 고정한다. 이 함수는 TCP 연결시도(12/28)만 받는다.
	return f.Network(at, event.NetworkInfo{
		ProcessPath: path,
		PID:         pid,
		Protocol:    event.ProtocolTCP,
		DestIP:      dest,
		DestPort:    port,
	}), true
}

// MapFile 은 CreateNewFile 속성 맵을 파일 이벤트로 바꾼다.
// 감시 경로로 안 거르면 Kernel-File 볼륨이 버퍼를 채워 다른 이벤트를 밀어낸다.
// 동작을 CREATE 로 고정한 것은 켜 둔 이벤트가 CreateNewFile(30) 하나뿐이기 때문이다.
// 해시는 붙이지 않는다. 아직 다 안 쓰인 파일의 해시는 맞을 리 없으면서 확인했다는 착각만 준다.
func MapFile(f event.Factory, at time.Time, props map[string]string, watchPaths []string) (event.Event, bool) {
	path := prop(props, propFileName)
	if path == "" || !underWatchPaths(path, watchPaths) {
		return event.Event{}, false
	}
	return f.File(at, event.FileInfo{Path: path, Action: event.FileActionCreate}), true
}

// MapDNS 는 DNS-Client 질의완료(3008) 속성 맵을 dns 이벤트로 바꾼다.
// pid 는 payload 에 없어 배선이 이벤트 헤더에서 꺼내 넘긴다. 해석에 실패해도 이벤트는 낸다.
func MapDNS(f event.Factory, at time.Time, props map[string]string, pid int, namer ProcessNamer) (event.Event, bool) {
	domain := normalizeDNSName(prop(props, propQueryName))
	if domain == "" {
		// 도메인 없는 DNS 이벤트는 조사에 쓸 데가 없다.
		return event.Event{}, false
	}
	// 역방향 조회는 IP 를 이름으로 바꾸는 질의라 "어디에 접속했나" 와 무관한데 양은 많다.
	if isReverseDNSName(domain) {
		return event.Event{}, false
	}

	path := ""
	if pid > 0 && namer != nil {
		path = namer.Name(pid)
	}

	detail := make(map[string]any, 3)
	if queryType := dnsQueryTypeLabel(prop(props, propQueryType)); queryType != "" {
		detail["queryType"] = queryType
	}
	if answers := parseDNSAnswers(prop(props, propQueryResults)); len(answers) > 0 {
		detail["answers"] = answers
	}
	// 0 도 담는다. 성공한 질의라는 사실이 실패와 구분되어야 한다.
	if status, err := strconv.Atoi(prop(props, propQueryStatus)); err == nil {
		detail["status"] = status
	}
	// Protocol 은 비워 둔다. 프로바이더가 안 알려 주는 값이라 채우면 지어낸 값을 관측으로 믿게 된다.
	return f.DNS(at, event.DNSInfo{ProcessPath: path, PID: pid, Domain: domain}, detail), true
}

// prop 은 속성을 꺼낸다. 정확한 이름으로 먼저 찾고 없으면 대소문자를 무시하고 한 번 더 찾는다.
// 두 번째 조회를 지우면 프로바이더 판마다 표기가 흔들릴 때 조용히 0건이 된다.
func prop(props map[string]string, key string) string {
	if v, ok := props[key]; ok {
		return strings.TrimSpace(v)
	}
	for k, v := range props {
		if strings.EqualFold(k, key) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func parsePID(s string) (int, bool) {
	pid, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}
