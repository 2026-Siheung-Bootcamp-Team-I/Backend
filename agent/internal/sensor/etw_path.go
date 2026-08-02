package sensor

import "strings"

// Windows 경로를 견줄 수 있는 모양으로 맞추고 감시 경로에 드는지 본다.
// 커널이 주는 경로와 서버가 내려준 경로는 표기가 달라 정규화 없이는 절대 안 맞는다.

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
