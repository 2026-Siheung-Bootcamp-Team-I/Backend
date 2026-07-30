// Package command 는 서버가 내려준 명령을 받아 실행하고 결과를 보고한다.
//
// 예전에는 서버가 셸/PowerShell 스크립트를 통째로 내려보내고 엔드포인트가 그걸 실행했다.
// 자체 에이전트에는 그런 임의 코드 실행 채널을 두지 않는다. 명령은 종류가 정해져 있고
// 실제 동작은 여기 Go 코드가 한다.
package command

import "strings"

// Matches 는 종료 대상 지정(target)이 실행 중인 프로세스 경로(procPath)를 가리키는지 판단한다.
//
// target 은 detector 가 알림에 실어 보낸 값이다. 전체 경로일 수도, 프로세스명일 수도,
// 인자가 붙은 명령행일 수도 있다.
//
// 규칙:
//   - 명령행이면 실행된 파일 자체(argv0)만 본다. 인자에 다른 경로가 들어 있어도 무시한다
//   - argv0 에 경로 구분자가 있으면 전체 경로가 같아야 한다. 같은 이름의 정상 프로세스를 지키기 위함이다
//   - 구분자가 없으면 파일명끼리 비교한다. 부분 일치는 쓰지 않는다
//
// caseInsensitive 는 Windows 에서 켠다. 경로 대소문자를 구분하지 않기 때문이다.
func Matches(target, procPath string, caseInsensitive bool) bool {
	wanted := argv0(target)
	if wanted == "" || procPath == "" {
		return false // 빈 대상이 전부와 매칭되면 기기의 모든 프로세스를 죽인다
	}
	actual := procPath
	if caseInsensitive {
		wanted = strings.ToLower(wanted)
		actual = strings.ToLower(actual)
	}
	if hasSeparator(wanted) {
		return wanted == actual
	}
	return wanted == basename(actual)
}

// argv0 는 명령행에서 실행된 파일 부분만 잘라낸다.
func argv0(cmdline string) string {
	trimmed := strings.TrimSpace(cmdline)
	if trimmed == "" {
		return ""
	}
	if space := strings.IndexAny(trimmed, " \t"); space >= 0 {
		return trimmed[:space]
	}
	return trimmed
}

func hasSeparator(path string) bool {
	return strings.ContainsAny(path, `/\`)
}

// basename 은 경로에서 파일명만 남긴다. 한 에이전트가 두 플랫폼을 다루므로 구분자를 둘 다 본다.
func basename(path string) string {
	if cut := strings.LastIndexAny(path, `/\`); cut >= 0 {
		return path[cut+1:]
	}
	return path
}
