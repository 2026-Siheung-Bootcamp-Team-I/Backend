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

// ETW 이벤트를 판정에 쓰는 이벤트로 바꾼다. 속성 맵만 받는 순수 함수라 빌드 태그 없이 둔다.
// etw_windows.go 는 콜백에서 속성을 꺼내 이 함수들에 넘기는 배선만 한다.

// ProcessNamer 는 PID 로 그 프로세스의 이름 또는 이미지 경로를 찾는다. 못 찾으면 빈 문자열이다.
type ProcessNamer interface {
	Name(pid int) string
}

const (
	// pidCacheTTL 은 캐시한 경로를 믿는 시간이다.
	// 길게 늘리면 Windows 가 재사용한 PID 의 새 프로세스에 죽은 프로세스 이름이 붙는다.
	pidCacheTTL = 2 * time.Second
	// pidCacheMax 는 항목 수 상한이다. 넘으면 통째로 비운다.
	// 상한을 풀면 오래 도는 에이전트에서 맵이 무한정 커진다.
	pidCacheMax = 1024
)

// pidCache 는 PID 를 이미지 경로로 푼 결과를 짧게 들고 있는다.
// 실제 조회는 Windows API 라 lookup 으로 주입받는다.
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
// 실패(빈 문자열)도 캐시한다. 안 하면 죽은 프로세스의 연결이 남은 동안 이벤트마다 조회를 다시 한다.
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

// normalizeDNSName 은 질의 이름을 집계할 수 있는 모양으로 맞춘다.
// 후행 점과 대소문자를 그대로 두면 같은 도메인이 대시보드에서 둘로 갈린다.
func normalizeDNSName(raw string) string {
	return strings.ToLower(strings.TrimRight(strings.TrimSpace(raw), "."))
}

// isReverseDNSName 은 IP 를 이름으로 되짚는 질의인지 본다.
func isReverseDNSName(name string) bool {
	return hasDNSSuffix(name, "in-addr.arpa") || hasDNSSuffix(name, "ip6.arpa")
}

// hasDNSSuffix 는 이름이 그 영역에 속하는지 본다.
// 라벨 경계까지 맞춘다. 단순 접미어 비교면 "notin-addr.arpa" 같은 이름까지 걸린다.
func hasDNSSuffix(name, suffix string) bool {
	return name == suffix || strings.HasSuffix(name, "."+suffix)
}

// dnsQueryTypeNames 는 자주 보는 레코드 종류다. 여기 없는 번호는 숫자 그대로 남긴다.
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

// dnsQueryTypeLabel 은 숫자로 오는 QueryType 을 이름으로 바꾼다. 모르는 번호는 그대로 둔다.
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
// 구분자를 실기기로 확인하지 못했다. 하나로 줄이면 잘못 짚었을 때 응답이 한 덩어리로 남는다.
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
// 번호 뒤에 공백이 없으면 IP 앞자리를 번호로 잘못 읽는 것이라 손대지 않는다.
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

// interpreters 는 script 로 분류할 실행 파일 이름이다.
var interpreters = map[string]bool{
	"powershell.exe": true,
	"cmd.exe":        true,
	"wscript.exe":    true,
	"cscript.exe":    true,
	"mshta.exe":      true,
}

// isInterpreter 는 이미지가 스크립트 인터프리터인지 본다.
// 경로 구분자를 요구하면 안 된다. ImageName 이 파일명만 올 때 Windows 스크립트 탐지가 통째로 죽는다.
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
// encodedcommand 를 빼면 탐지에 쓸모는 있어도 거기 실려 오는 자격증명이 로그에 그대로 남는다.
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
// "-Password hunter2" 와 "/token:abc", "--password=abc" 형태를 모두 다룬다.
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
// 안 바꾸면 argv0 이 "powershell.exe" 뿐이라 %TEMP% 실행에도 R2/R3 CRITICAL 룰이 발화하지 않는다.
// 경로를 모를 때는 손대지 않는다. 파일명으로 덮으면 원래 명령행이 담던 정보만 잃는다.
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
// 옵션 접두사가 없으면 이름을 비워 돌려준다. 경로가 옵션으로 걸리지 않게 하려는 것이다.
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
// `*` 를 문자 그대로 비교하면 사용자별 시작프로그램이 안 걸려 T1547 판정이 통째로 빈다.
// 여러 단계를 건너뛰게 넓히지도 마라. 감시 범위가 의도보다 커진다.
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
// 볼륨 표기를 안 떼면 커널의 장치 경로와 서버의 드라이브 경로가 접두어 비교에서 절대 안 맞는다.
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

// ETW 세션 생성이 실패하는 대표적인 두 가지 Windows 오류 코드. 조치가 정반대라 갈라 준다.
const (
	winErrorAccessDenied  = 5   // ERROR_ACCESS_DENIED
	winErrorAlreadyExists = 183 // ERROR_ALREADY_EXISTS
)

// sessionErrorHint 는 세션 생성 실패 원인에 맞는 조치를 한 줄로 돌려준다.
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
