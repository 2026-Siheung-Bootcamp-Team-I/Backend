package command

import "testing"

// 대상 매칭은 조치의 정확도를 정하는 부분이다.
// 너무 넓게 잡으면 멀쩡한 프로세스를 죽이고, 너무 좁게 잡으면 공격 도구를 놓친다.

func TestMatchesByBasenameWhenTargetHasNoPath(t *testing.T) {
	// detector 가 전체 경로를 못 구하면 프로세스명만 보낸다.
	cases := map[string]bool{
		"/usr/bin/curl":            true,
		"/opt/homebrew/bin/curl":   true,
		`C:\Windows\System32\curl`: true,
		"/usr/bin/curlx":           false, // 부분 일치로 잡으면 안 된다
		"/usr/bin/xcurl":           false,
		"/usr/bin/wget":            false,
	}
	for path, want := range cases {
		if got := Matches("curl", path, false); got != want {
			t.Errorf("Matches(curl, %q) = %v, want %v", path, got, want)
		}
	}
}

func TestMatchesByFullPathWhenTargetHasPath(t *testing.T) {
	// 경로가 오면 그 경로로 뜬 프로세스만 죽인다. 같은 이름의 정상 프로세스를 지키기 위함이다.
	if !Matches("/tmp/evil.sh", "/tmp/evil.sh", false) {
		t.Error("같은 전체 경로는 매칭돼야 한다")
	}
	if Matches("/tmp/evil.sh", "/usr/local/bin/evil.sh", false) {
		t.Error("이름만 같고 경로가 다르면 매칭되면 안 된다")
	}
}

func TestMatchesUsesArgv0WhenTargetIsCommandLine(t *testing.T) {
	// detector 의 actTarget 은 cmdline 이 있으면 그걸 그대로 보낸다. 인자가 붙어 있다.
	// 실행된 파일 자체로 판단해야 한다.
	if !Matches("/tmp/evil.sh --loop 5", "/tmp/evil.sh", false) {
		t.Error("cmdline 의 argv0 로 매칭돼야 한다")
	}
	if !Matches("sh /tmp/x.sh", "/bin/sh", false) {
		t.Error("argv0 가 sh 면 /bin/sh 와 매칭돼야 한다")
	}
}

func TestMatchesIsCaseInsensitiveOnWindows(t *testing.T) {
	// Windows 는 경로 대소문자를 구분하지 않는다. ETW 가 주는 표기와 알림에 담긴 표기가 다를 수 있다.
	if !Matches("CURL.EXE", `C:\Windows\System32\curl.exe`, true) {
		t.Error("Windows 에서는 대소문자를 무시해야 한다")
	}
	if Matches("CURL.EXE", "/usr/bin/curl.exe", false) {
		t.Error("Windows 가 아니면 대소문자를 구분해야 한다")
	}
}

func TestMatchesRejectsEmptyTarget(t *testing.T) {
	// 빈 대상이 전부와 매칭되면 기기의 모든 프로세스를 죽인다.
	for _, path := range []string{"/usr/bin/curl", "", "/bin/sh"} {
		if Matches("", path, false) {
			t.Errorf("빈 target 이 %q 와 매칭됐다", path)
		}
	}
	if Matches("curl", "", false) {
		t.Error("빈 경로가 매칭됐다")
	}
}

func TestArgv0(t *testing.T) {
	cases := map[string]string{
		"/tmp/evil.sh --loop 5": "/tmp/evil.sh",
		"  /tmp/evil.sh  ":      "/tmp/evil.sh",
		"curl":                  "curl",
		"":                      "",
		`C:\tools\a.exe -x`:     `C:\tools\a.exe`,
	}
	for input, want := range cases {
		if got := argv0(input); got != want {
			t.Errorf("argv0(%q) = %q, want %q", input, got, want)
		}
	}
}
