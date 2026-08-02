package main

import (
	"io"
	"os"
	"path/filepath"
)

// openLogWriter 는 로그를 쓸 곳을 연다. 경로가 비면 stderr 를 쓰며, 돌려주는 닫기 함수는 어느 경우든 부를 수 있다.
func openLogWriter(path string) (io.Writer, func() error, error) {
	if path == "" {
		return os.Stderr, func() error { return nil }, nil
	}
	// 서비스로 처음 뜰 때 상위 폴더가 아직 없다. 여기서 죽으면 그 사실조차 안 보인다.
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, nil, err
		}
	}
	// 이어 쓴다. 재시작할 때마다 지우면 직전 실행이 왜 죽었는지가 사라진다.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, err
	}
	return f, f.Close, nil
}
