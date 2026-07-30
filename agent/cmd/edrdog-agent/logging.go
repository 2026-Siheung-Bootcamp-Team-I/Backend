package main

import (
	"io"
	"os"
	"path/filepath"
)

// openLogWriter 는 로그를 쓸 곳을 연다. 경로가 비면 stderr 를 그대로 쓴다.
//
// 이게 필요한 이유는 Windows 다. macOS 는 LaunchDaemon 의 StandardOutPath 가 stderr 를
// 파일로 받아 주지만, Windows 서비스는 stderr 가 아무 데도 가지 않는다. 그대로 두면
// 에이전트가 왜 안 붙는지, pktmon 이 프레임을 왜 한 건도 못 넘기는지 볼 방법이 없다.
// 이유별 카운터를 애써 남겨 놨는데 읽을 수가 없으면 없는 것과 같다.
//
// 돌려주는 함수는 항상 부를 수 있다. stderr 인 경우엔 아무것도 하지 않는다.
func openLogWriter(path string) (io.Writer, func() error, error) {
	if path == "" {
		return os.Stderr, func() error { return nil }, nil
	}
	// 서비스로 처음 뜰 때 상위 폴더가 아직 없을 수 있다. 거기서 죽으면 그 사실조차 안 보인다.
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, nil, err
		}
	}
	// 이어 쓴다. 재시작할 때마다 지우면 직전 실행이 왜 죽었는지가 사라진다.
	// 0600 인 이유는 어느 호스트가 어디에 붙었는지가 로그에 남기 때문이다.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, err
	}
	return f, f.Close, nil
}
