//go:build !darwin && !windows

package main

import (
	"log/slog"

	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/event"
	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/runtime"
	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/transport"
)

// platformSensors 는 지원하지 않는 플랫폼에서 빈 목록을 돌려준다.
//
// 대상은 macOS 와 Windows 뿐이다. 그래도 다른 OS 에서 빌드가 깨지지 않게 자리를 만들어 둔다.
// 센서가 없으면 main 이 기동을 거부하므로 조용히 0건으로 도는 일은 없다.
func platformSensors(event.Factory, transport.ServerConfig, *slog.Logger) []runtime.Sensor {
	return nil
}
