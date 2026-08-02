package sensor

import "strings"

// Windows 명령행을 토큰으로 쪼개 argv0 을 바로잡고 비밀값을 가린다.
// 토큰 사이의 간격을 그대로 되돌린다. 정규화하면 서버에 남는 명령행이 원본과 달라진다.

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
