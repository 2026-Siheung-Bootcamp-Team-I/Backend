//go:build !darwin && !windows

package main

import (
	"log/slog"

	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/event"
	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/runtime"
	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/transport"
)

// platformSensors 는 지원하지 않는 플랫폼에서 빈 목록을 돌려준다. 빌드만 통과시키는 자리다.
func platformSensors(event.Factory, transport.ServerConfig, *slog.Logger) []runtime.Sensor {
	return nil
}
