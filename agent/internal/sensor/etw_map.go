package sensor

import (
	"errors"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/event"
)

// 이 파일에는 빌드 태그가 없다.
//
// ETW 세션을 여는 코드는 Windows 에서만 컴파일되지만, 그러면 로직을 개발 기기에서 한 번도
// 검증할 수 없다. 그래서 판정에 관여하는 부분을 전부 여기로 빼서 속성 맵(map[string]string)만
// 입력으로 받는 순수 함수로 만들었다. etw_windows.go 는 콜백에서 속성을 꺼내 이 함수들에
// 넘기는 배선만 한다.
//
// 속성 이름은 각 프로바이더의 매니페스트에 정의된 이름 그대로다.
//   - Microsoft-Windows-Kernel-Process ProcessStart(1): ProcessID, ProcessSequenceNumber, CreateTime,
//     ParentProcessID, SessionID, Flags, ImageName, ImageChecksum, ...
//     여기에 CommandLine 은 없다. 어느 판에도 없다. 커널이 다른 프로세스의 명령행을 ETW 로
//     내보내지 않기 때문이고, ImageName 도 EPROCESS 의 짧은 이름이라 파일명까지만 온다.
//     그래서 ImagePath 와 CommandLine 은 배선이 프로세스를 직접 조회해 채워 넣는다.
//   - Microsoft-Windows-Kernel-Network TCP 연결시도(12=IPv4, 28=IPv6): PID, size, daddr, saddr, dport, sport
//     PID 가 실려 오는 것이 이 수집기의 전제다. Zeek 는 패킷만 봐서 이걸 못 했다.
//   - Microsoft-Windows-Kernel-File NameCreate(10)/DeletePath(26)/RenamePath(27)/CreateNewFile(30): FileName
//   - Microsoft-Windows-DNS-Client 질의발신(3006): QueryName, QueryType, QueryOptions, ServerList, ...
//     질의완료(3008): QueryName, QueryType, QueryOptions, QueryStatus, QueryResults
//     둘 다 payload 에 PID 가 없다. ClientPID 는 3010 계열에만 있어서 배선이 이벤트 헤더의
//     ProcessID 를 대신 넘긴다.

// ProcessNamer 는 PID 로 그 프로세스의 이름 또는 이미지 경로를 찾는다.
//
// ETW 는 부모를 PID 로만 알려주는데 서버 스키마의 parent 는 이름이다. 네트워크 이벤트도
// 마찬가지로 PID 만 실려 온다. 해석은 살아 있는 프로세스를 봐야 하는 일이라 순수하지 않으므로
// 인터페이스로 빼서 주입받는다. 찾지 못하면 빈 문자열을 준다.
type ProcessNamer interface {
	Name(pid int) string
}

const (
	// pidCacheTTL 은 캐시한 경로를 믿는 시간이다.
	//
	// 무한 캐시를 두면 안 되는 이유는 Windows 가 PID 를 금방 재사용하기 때문이다. 죽은 프로세스의
	// 경로를 계속 들고 있으면 같은 번호로 새로 뜬 프로세스의 연결에 엉뚱한 이름을 붙이게 되는데,
	// 그건 이름이 없는 것보다 나쁘다. 조사하는 사람이 틀린 이름을 믿고 따라가기 때문이다.
	// 짧게 잡아 두면 브라우저처럼 오래 사는 프로세스의 연속된 연결에는 캐시가 그대로 먹힌다.
	pidCacheTTL = 2 * time.Second
	// pidCacheMax 는 항목 수 상한이다. 넘으면 통째로 비운다.
	// 오래 도는 에이전트에서 맵이 무한정 커지는 것만 막으면 되므로 정교한 축출은 필요 없다.
	pidCacheMax = 1024
)

// pidCache 는 PID 를 이미지 경로로 푼 결과를 짧게 들고 있는다.
//
// 캐시가 필요한 이유는 네트워크 이벤트마다 해석이 불리기 때문이다. 연결이 초당 수백 건이면
// 그때마다 프로세스를 여는 비용이 그대로 쌓인다.
//
// 실제 조회는 lookup 으로 주입받는다. 조회가 Windows API 라 이 파일에서 할 수 없기도 하고,
// 그렇게 해야 만료와 상한 같은 판정 가능한 부분을 개발 기기에서 검증할 수 있다.
type pidCache struct {
	mu      sync.Mutex
	entries map[int]pidEntry
	lookup  func(pid int) string
	// now 가 비면 time.Now 를 쓴다. 만료를 테스트에서 흔들어 보려고 둔다.
	now func() time.Time
}

type pidEntry struct {
	path string
	at   time.Time
}

// Name 은 PID 의 이미지 경로를 준다. ProcessNamer 를 만족한다.
//
// 조회에 실패한 결과(빈 문자열)도 캐시한다. 실패는 대개 프로세스가 이미 죽었거나 권한이 없어서인데
// 둘 다 곧바로 다시 시도해도 마찬가지다. 캐시하지 않으면 죽은 프로세스의 연결이 남아 있는 동안
// 이벤트마다 조회를 다시 하게 된다.
func (c *pidCache) Name(pid int) string {
	now := c.clock()

	c.mu.Lock()
	if e, ok := c.entries[pid]; ok && now.Sub(e.at) < pidCacheTTL {
		c.mu.Unlock()
		return e.path
	}
	c.mu.Unlock()

	// 조회는 락 밖에서 한다. 조회가 막히면 다른 이벤트 처리까지 같이 멈춘다.
	path := c.lookup(pid)

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil || len(c.entries) >= pidCacheMax {
		c.entries = make(map[int]pidEntry, pidCacheMax)
	}
	c.entries[pid] = pidEntry{path: path, at: now}
	return path
}

func (c *pidCache) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// ETW 속성 이름. 매니페스트 정의와 같아야 한다.
const (
	propImageName       = "ImageName"
	propParentProcessID = "ParentProcessID"
	propPID             = "PID"
	propDestAddr        = "daddr"
	propDestPort        = "dport"
	propFileName        = "FileName"
	propQueryName       = "QueryName"
	propQueryType       = "QueryType"
	propQueryStatus     = "QueryStatus"
	propQueryResults    = "QueryResults"

	// 아래 둘은 매니페스트에 없다. ProcessStart 에는 전체 경로도 명령행도 실려 오지 않아
	// 배선(etw_windows.go)이 살아 있는 프로세스를 조회해 같은 맵에 채워 넣는다.
	// 여기서 속성으로 받는 이유는 조회가 Windows API 라 이 파일에서 할 수 없기 때문이다.
	propImagePath   = "ImagePath"
	propCommandLine = "CommandLine"
)

// MapProcess 는 ProcessStart 속성 맵을 프로세스 또는 스크립트 이벤트로 바꾼다.
//
// ETW 만으로는 이미지의 전체 경로도 명령행도 알 수 없다. 매니페스트의 ImageName 은 커널
// EPROCESS 의 짧은 이름이라 구조적으로 파일명까지만 담고(실기기에서 "svchost.exe" 로 관측),
// CommandLine 은 어느 판에도 아예 없다. 그래서 배선이 PID 로 살아 있는 프로세스를 조회해
// ImagePath 와 CommandLine 을 채워 넣는다.
//
// 그 조회는 실패할 수 있다. 프로세스가 이미 죽었거나 권한이 모자란 경우다. 그때는 파일명만
// 남은 ImageName 으로 물러나되 이벤트 자체는 내보낸다. 실행 사실을 통째로 잃는 쪽이 더 나쁘다.
func MapProcess(f event.Factory, at time.Time, props map[string]string, namer ProcessNamer) (event.Event, bool) {
	// 전체 경로를 알면 그쪽을 쓴다. detector 의 R2/R3 룰이 경로에서 \temp\ 같은 표식을 찾으므로
	// 파일명만으로는 판정이 서지 않는다.
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
	// 전체 경로도 명령행도 없으면 cmdline 은 빈 채로 둔다. 파일명만 넣어 봐야 판정에 쓸 값이
	// 아니면서 responder 의 조치 대상만 이름으로 흐려 놓는다.
	cmdline = redactSecrets(cmdline)

	parent := ""
	if ppid, ok := parsePID(prop(props, propParentProcessID)); ok && namer != nil {
		parent = baseName(namer.Name(ppid))
	}

	// 인터프리터는 script 로 낸다. detector 가 script 타입에만 T1059 룰을 건다.
	if isInterpreter(exe) {
		return f.Script(at, exe, cmdline, parent), true
	}
	return f.Process(at, exe, cmdline, parent), true
}

// MapNetwork 는 TCP 연결시도 속성 맵을 네트워크 이벤트로 바꾼다.
//
// PID 로 프로세스를 풀어 넣는 것이 자체 수집기를 만든 이유다. Zeek 는 패킷만 보므로 누가
// 연결했는지 알 수 없었다. 다만 짧게 살다 죽는 프로세스는 해석에 실패할 수 있는데, 그렇다고
// 이벤트를 버리면 목적지 IP 기반 판정까지 같이 잃는다. 그래서 프로세스명 없이도 내보낸다.
func MapNetwork(f event.Factory, at time.Time, props map[string]string, namer ProcessNamer) (event.Event, bool) {
	dest := prop(props, propDestAddr)
	// 공인 IP 판정은 netsnap.go 의 IsPublic 을 그대로 쓴다. 같은 패키지이고 macOS 쪽 네트워크
	// 센서와 기준이 갈리면 같은 목적지를 플랫폼마다 다르게 거르게 된다.
	if !IsPublic(dest) {
		return event.Event{}, false
	}

	path := ""
	if pid, ok := parsePID(prop(props, propPID)); ok && namer != nil {
		path = namer.Name(pid)
	}

	// 포트에 ntohs 를 걸지 않는다. 매니페스트의 outType 이 win:Port 이고 MS 문서는 "이 값을
	// ntohs 에 넘기라"고 하지만, 그건 원시 payload 를 직접 읽을 때 이야기다. 우리는 TDH 가
	// 렌더링해 준 값을 받으므로 이미 호스트 바이트 오더의 십진수다. 여기서 한 번 더 뒤집으면
	// 443 이 47873 이 된다.
	//
	// 이건 아직 실기기에서 확인하지 못한 가정이다. destPort 가 뒤집힌 값으로 보이면 그때
	// 여기에 변환을 넣어라. 문서만 보고 미리 넣지 마라.
	port, _ := strconv.Atoi(strings.TrimSpace(prop(props, propDestPort)))
	if port < 0 || port > 65535 {
		port = 0
	}
	return f.Network(at, path, dest, port), true
}

// MapFile 은 CreateNewFile 속성 맵을 파일 이벤트로 바꾼다.
//
// Kernel-File 은 볼륨이 엄청나므로 감시 대상 경로로 시작하는 것만 통과시킨다.
// watchPaths 가 비면 아무것도 내보내지 않는다. 기준이 없는 상태에서 전부 흘리면 버퍼가
// 파일 이벤트로 가득 차 정작 중요한 이벤트가 밀려난다.
func MapFile(f event.Factory, at time.Time, props map[string]string, watchPaths []string) (event.Event, bool) {
	path := prop(props, propFileName)
	if path == "" || !underWatchPaths(path, watchPaths) {
		return event.Event{}, false
	}
	return f.File(at, path), true
}

// MapDNS 는 DNS-Client 질의완료(3008) 속성 맵을 dns 이벤트로 바꾼다.
//
// pid 는 배선이 이벤트 헤더에서 꺼내 넘긴다. 3006/3008 payload 에는 PID 가 없기 때문이다.
// 해석에 실패해도 이벤트는 내보낸다. 어떤 도메인이 조회됐는지가 이 이벤트의 본체이고,
// 프로세스는 곁가지다.
//
// detector 는 DNS 를 판정에 쓰지 않는다. 조사 화면에서 "이 호스트가 어디를 찾았나" 를 보는
// 용도라, 집계에 방해가 되는 표기 흔들림(후행 점, 대소문자)과 양만 많은 역방향 조회를 여기서
// 정리한다.
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
	// 0 도 담는다. 성공한 질의라는 사실이 실패와 구분되어야 조사에서 쓸모가 있다.
	if status, err := strconv.Atoi(prop(props, propQueryStatus)); err == nil {
		detail["status"] = status
	}
	return f.DNS(at, path, domain, detail), true
}

// normalizeDNSName 은 질의 이름을 집계할 수 있는 모양으로 맞춘다.
//
// 후행 점을 떼는 이유는 DNS 이름이 "example.com." 처럼 루트 점을 달고 오는 경우가 있어서다.
// 그대로 두면 대시보드에서 같은 도메인이 둘로 갈린다. 소문자로 맞추는 이유도 같다. DNS 는
// 대소문자를 구분하지 않는데 표기를 그대로 두면 "Example.COM" 과 "example.com" 이 따로 센다.
func normalizeDNSName(raw string) string {
	return strings.ToLower(strings.TrimRight(strings.TrimSpace(raw), "."))
}

// isReverseDNSName 은 IP 를 이름으로 되짚는 질의인지 본다.
func isReverseDNSName(name string) bool {
	return hasDNSSuffix(name, "in-addr.arpa") || hasDNSSuffix(name, "ip6.arpa")
}

// hasDNSSuffix 는 이름이 그 영역에 속하는지 본다. 라벨 경계에서만 맞는다고 본다.
// 단순 접미어 비교를 하면 "notin-addr.arpa" 같은 이름까지 걸린다.
func hasDNSSuffix(name, suffix string) bool {
	return name == suffix || strings.HasSuffix(name, "."+suffix)
}

// dnsQueryTypeNames 는 자주 보는 레코드 종류다. 여기 없는 번호는 숫자 그대로 남긴다.
// 표를 다 채우는 것이 목적이 아니라 조사 화면에서 흔한 값이 읽히게 하는 것이 목적이다.
var dnsQueryTypeNames = map[int]string{
	1:   "A",
	2:   "NS",
	5:   "CNAME",
	6:   "SOA",
	12:  "PTR",
	15:  "MX",
	16:  "TXT",
	28:  "AAAA",
	33:  "SRV",
	64:  "SVCB",
	65:  "HTTPS",
	255: "ANY",
}

// dnsQueryTypeLabel 은 숫자로 오는 QueryType 을 이름으로 바꾼다.
// 모르는 번호는 지어내지 않고 원래 값을 그대로 둔다. 틀린 이름을 붙이는 쪽이 나쁘다.
func dnsQueryTypeLabel(raw string) string {
	n, err := strconv.Atoi(raw)
	if err != nil {
		return raw
	}
	if name, ok := dnsQueryTypeNames[n]; ok {
		return name
	}
	return raw
}

// parseDNSAnswers 는 QueryResults 를 응답 값 목록으로 쪼갠다.
//
// 구분자가 세미콜론이라고 알려져 있으나 실기기로 확인하지 못했다. 잘못 짚으면 응답 전체가
// 한 덩어리 문자열로 남는데, 그건 틀린 값이 아니라 쓸 수 없는 값이다. 그래서 세미콜론과
// 쉼표를 모두 구분자로 본다. 둘 다 응답 값 안에는 나오지 않으므로 둘 다 봐도 손해가 없다.
func parseDNSAnswers(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool { return r == ';' || r == ',' })
	answers := make([]string, 0, len(fields))
	for _, field := range fields {
		if v := stripDNSResultPrefix(field); v != "" {
			answers = append(answers, v)
		}
	}
	if len(answers) == 0 {
		return nil
	}
	return answers
}

// stripDNSResultPrefix 는 "type: 5 alias.example.com" 처럼 값 앞에 붙는 레코드 종류를 뗀다.
//
// 그 번호는 detail 의 queryType 과 겹치는 값이라 남겨 봐야 응답 IP 를 그대로 쓰지 못하게만 한다.
// 번호 뒤에 공백이 없으면 값의 일부로 보고 손대지 않는다. "93.184.216.34" 의 앞자리를 번호로
// 잘못 읽어 ".184.216.34" 를 남기는 사고를 막는다.
func stripDNSResultPrefix(token string) string {
	v := strings.TrimSpace(token)

	const prefix = "type:"
	if len(v) < len(prefix) || !strings.EqualFold(v[:len(prefix)], prefix) {
		return v
	}
	v = strings.TrimSpace(v[len(prefix):])

	digits := 0
	for digits < len(v) && v[digits] >= '0' && v[digits] <= '9' {
		digits++
	}
	if digits == 0 || digits == len(v) {
		// 번호만 있고 값이 없으면 담을 것이 없다.
		return v[digits:]
	}
	if v[digits] != ' ' && v[digits] != '\t' {
		return v
	}
	return strings.TrimSpace(v[digits:])
}

// prop 은 속성을 꺼낸다. 정확한 이름으로 먼저 찾고 없으면 대소문자를 무시하고 한 번 더 찾는다.
// 프로바이더 버전에 따라 표기가 흔들려도 조용히 0건이 되지 않게 하려는 보호막이다.
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

// interpreters 는 script 로 분류할 실행 파일 이름이다.
var interpreters = map[string]bool{
	"powershell.exe": true,
	"cmd.exe":        true,
	"wscript.exe":    true,
	"cscript.exe":    true,
	"mshta.exe":      true,
}

// isInterpreter 는 이미지가 스크립트 인터프리터인지 본다.
//
// ETW 의 ImageName 은 "\Device\HarddiskVolume4\Windows\System32\cmd.exe" 같은 장치 경로일
// 수도, 실기기에서 관측된 것처럼 "svchost.exe" 처럼 파일명만일 수도 있다. 그래서 경로 구분자를
// 요구하지 않고 파일명만 뽑아 비교한다. 구분자를 요구하는 매칭(LIKE '%\powershell.exe')은
// 파일명만 올 때 절대 걸리지 않아 Windows 스크립트 탐지가 통째로 죽는다.
func isInterpreter(image string) bool {
	name := strings.ToLower(baseName(image))
	if interpreters[name] {
		return true
	}
	// python.exe, python3.exe, python3.12.exe 처럼 버전이 붙는다.
	return strings.HasPrefix(name, "python") && strings.HasSuffix(name, ".exe")
}

// baseName 은 경로에서 파일명만 남긴다. 구분자는 둘 다 본다.
func baseName(path string) string {
	if i := strings.LastIndexAny(path, `/\`); i >= 0 {
		return path[i+1:]
	}
	return path
}

// secretFlags 는 뒤에 오는 값이 로그에 남으면 안 되는 옵션 이름이다.
//
// EncodedCommand 의 base64 는 탐지에 쓸모가 크지만, 자격증명이 그대로 실려 오는 경우가 있어
// 같이 가린다. 수집기가 남긴 로그가 자격증명 유출 경로가 되는 것이 더 나쁘다.
var secretFlags = map[string]bool{
	"password":       true,
	"passwd":         true,
	"pass":           true,
	"token":          true,
	"secret":         true,
	"apikey":         true,
	"credential":     true,
	"encodedcommand": true,
	"encoded":        true,
	"enc":            true,
}

const redacted = "<redacted>"

// redactSecrets 는 비밀값 옵션 뒤의 값을 가린다.
//
// "-Password hunter2" 처럼 다음 토큰에 오는 형태와 "/token:abc", "--password=abc" 처럼
// 옵션에 붙는 형태를 모두 다룬다. 구분자와 원래 간격은 그대로 두어 사람이 읽을 수 있게 남긴다.
func redactSecrets(cmdline string) string {
	tokens := splitCmdline(cmdline)
	hideNext := false

	for i := range tokens {
		if hideNext {
			tokens[i].text = redacted
			hideNext = false
			continue
		}
		name, sep, hasValue := parseFlag(tokens[i].text)
		if !secretFlags[name] {
			continue
		}
		if hasValue {
			tokens[i].text = tokens[i].text[:len(tokens[i].text)-len(valueOf(tokens[i].text, sep))] + redacted
			continue
		}
		hideNext = true
	}

	return joinCmdline(tokens)
}

// withArgv0 은 명령행의 첫 토큰을 실행 파일 경로로 바꾼다.
//
// detector 의 R2/R3 룰은 cmdline 의 첫 토큰만 떼어 거기서 \temp\ 같은 표식을 찾는다
// (Rules.java 의 executableHasMarker). 그런데 Windows 의 명령행 argv0 은 커널이 아니라
// 프로세스를 띄운 쪽이 정하는 값이라 "powershell.exe -enc ..." 처럼 경로 없이 오는 일이 흔하다.
// 그대로 두면 실행 파일이 %TEMP% 에 있어도 CRITICAL 룰이 발화하지 않는다.
// macOS 쪽 eslCmdline 도 같은 이유로 argv0 을 실행 파일 경로로 덮어쓴다.
//
// 경로를 모를 때(파일명만 아는 경우)는 손대지 않는다. 파일명으로 바꿔 봐야 나아지지 않고,
// 원래 명령행이 담고 있던 정보만 잃는다.
func withArgv0(cmdline, exePath string) string {
	if !hasPathSeparator(exePath) {
		return cmdline
	}
	tokens := splitCmdline(cmdline)
	if len(tokens) == 0 {
		return exePath
	}
	tokens[0].text = exePath
	return joinCmdline(tokens)
}

// joinCmdline 은 쪼갠 토큰을 원래 간격 그대로 다시 잇는다.
func joinCmdline(tokens []cmdToken) string {
	var b strings.Builder
	for _, t := range tokens {
		b.WriteString(t.text)
		b.WriteString(t.sep)
	}
	return b.String()
}

// hasPathSeparator 는 값이 파일명이 아니라 경로인지 본다. 구분자는 둘 다 본다.
func hasPathSeparator(p string) bool {
	return strings.ContainsAny(p, `/\`)
}

type cmdToken struct {
	text string
	sep  string // 뒤따르던 공백. 원래 모양대로 되돌리기 위해 들고 있는다
}

// splitCmdline 은 명령행을 공백으로 나눈다. 큰따옴표 안의 공백은 나누지 않는다.
func splitCmdline(s string) []cmdToken {
	var out []cmdToken
	i := 0
	for i < len(s) {
		start := i
		quoted := false
		for i < len(s) {
			c := s[i]
			if c == '"' {
				quoted = !quoted
			}
			if !quoted && (c == ' ' || c == '\t') {
				break
			}
			i++
		}
		text := s[start:i]
		sepStart := i
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		out = append(out, cmdToken{text: text, sep: s[sepStart:i]})
	}
	return out
}

// parseFlag 는 토큰이 옵션이면 접두사를 뗀 이름과, 값이 붙어 있으면 그 구분자를 준다.
// 옵션 접두사가 없으면 이름을 비워 돌려준다. 그래야 "C:\pass\x.exe" 같은 경로가 걸리지 않는다.
func parseFlag(tok string) (name, sep string, hasValue bool) {
	trimmed := strings.TrimLeft(tok, "-/")
	if len(trimmed) == len(tok) || trimmed == "" {
		return "", "", false
	}
	if i := strings.IndexAny(trimmed, "=:"); i >= 0 {
		return strings.ToLower(trimmed[:i]), trimmed[i : i+1], true
	}
	return strings.ToLower(trimmed), "", false
}

// valueOf 는 "--password=abc" 에서 구분자 뒤의 "abc" 를 준다.
func valueOf(tok, sep string) string {
	if i := strings.Index(tok, sep); i >= 0 {
		return tok[i+1:]
	}
	return ""
}

// underWatchPaths 는 경로가 감시 대상 중 하나의 아래에 있는지 본다.
func underWatchPaths(path string, watchPaths []string) bool {
	target := normalizeWinPath(path)
	if target == "" {
		return false
	}
	for _, w := range watchPaths {
		prefix := normalizeWinPath(w)
		if prefix == "" {
			continue
		}
		prefix = strings.TrimSuffix(prefix, `\`)
		if matchesWatchPath(target, prefix) {
			return true
		}
	}
	return false
}

// matchesWatchPath 는 경로가 감시 경로 아래에 있는지 본다. 감시 경로의 `*` 는 한 단계를 대신한다.
//
// 서버는 사용자별 시작프로그램 경로를 계정 자리에 `*` 를 넣어 내려준다
// (`C:\Users\*\AppData\Roaming\...\Startup`). 계정 이름을 서버가 알 수 없기 때문이다.
// 문자 그대로 비교하면 이 경로는 영영 안 걸리고, 사용자별 시작프로그램에 무엇이 생겨도
// 지속성 확보(T1547) 판정이 통째로 빈다.
//
// `*` 는 한 단계만 대신한다. 여러 단계를 건너뛰게 하면 감시 범위가 의도보다 넓어진다.
func matchesWatchPath(target, prefix string) bool {
	if !strings.Contains(prefix, "*") {
		return target == prefix || strings.HasPrefix(target, prefix+`\`)
	}

	want := strings.Split(prefix, `\`)
	got := strings.Split(target, `\`)
	if len(got) < len(want) {
		return false
	}
	for i, segment := range want {
		if segment == "*" {
			continue // 어떤 한 단계든 통과
		}
		if got[i] != segment {
			return false
		}
	}
	return true
}

// normalizeWinPath 는 두 경로를 견줄 수 있는 모양으로 맞춘다.
//
// Kernel-File 이 주는 경로는 "\Device\HarddiskVolume3\Users\a\x.lnk" 같은 장치 경로인데
// 서버가 내려주는 watch_paths 는 "C:\Users\a" 같은 드라이브 경로다. 그대로 접두어 비교를 하면
// 절대 맞지 않으므로 양쪽에서 볼륨 표기를 떼고 나머지로 견준다. 볼륨을 무시하는 셈이라
// 드라이브가 여럿이면 다른 드라이브의 같은 경로도 걸리는데, 감시 대상이 시스템 드라이브의
// 자동실행 경로라 실질적인 오탐이 되지 않는다. 볼륨 번호와 드라이브 문자를 맞추려면 별도
// API 가 필요한데 그 비용을 낼 만한 이득이 아니다.
//
// Windows 는 경로 대소문자를 구분하지 않으므로 소문자로 맞춘다.
func normalizeWinPath(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	p = strings.ReplaceAll(p, "/", `\`)
	p = strings.TrimPrefix(p, `\??\`)

	if rest, ok := stripDeviceVolume(p); ok {
		return rest
	}
	if len(p) >= 2 && p[1] == ':' && isAlpha(p[0]) {
		return p[2:]
	}
	return p
}

// stripDeviceVolume 은 "\device\harddiskvolume3" 접두어를 뗀다.
func stripDeviceVolume(p string) (string, bool) {
	const prefix = `\device\harddiskvolume`
	if !strings.HasPrefix(p, prefix) {
		return "", false
	}
	rest := p[len(prefix):]
	digits := 0
	for digits < len(rest) && rest[digits] >= '0' && rest[digits] <= '9' {
		digits++
	}
	if digits == 0 {
		return "", false
	}
	return rest[digits:], true
}

func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// ETW 세션 생성이 실패하는 대표적인 두 가지 Windows 오류 코드.
// 조치가 정반대라 로그에서 갈라 주어야 원인을 빨리 찾는다.
const (
	winErrorAccessDenied  = 5   // ERROR_ACCESS_DENIED
	winErrorAlreadyExists = 183 // ERROR_ALREADY_EXISTS
)

// sessionErrorHint 는 세션 생성 실패 원인에 맞는 조치를 한 줄로 돌려준다.
//
// 이 프로젝트에서 가장 찾기 어려웠던 고장이 전부 "조용히 0건" 이었다. 실기기에 접근할 수 없는
// 상태에서는 오류 메시지가 원인 파악의 거의 전부라, 두 경우를 구분해 준다.
//
// 코드 값은 Windows 것이다. 이 함수를 빌드 태그 없는 파일에 두는 이유는 개발 기기에서
// 검증하기 위해서다.
func sessionErrorHint(err error, sessionName string) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch uintptr(errno) {
		case winErrorAlreadyExists:
			return "같은 이름의 세션이 이미 돌고 있다. logman stop " + sessionName + " -ets 로 지워라"
		case winErrorAccessDenied:
			return "권한이 없다. 관리자 권한으로 실행하거나 Performance Log Users 그룹에 넣어라. " +
				"서비스로 돌린다면 LocalSystem 이어야 한다"
		}
	}
	// 코드를 못 알아보면 가장 흔한 원인을 안내한다.
	return "관리자 권한으로 실행해야 한다"
}
