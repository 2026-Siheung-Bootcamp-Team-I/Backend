//go:build !windows

package main

import (
	"fmt"
	"log/slog"
)

// runAsService 는 Windows 밖에서는 쓸 일이 없다.
// macOS 는 LaunchDaemon 이 일반 프로세스를 그대로 돌리므로 서비스 제어 핸들러가 필요 없다.
func runAsService(options, *slog.Logger) error {
	return fmt.Errorf("-service 는 Windows 에서만 쓴다")
}
