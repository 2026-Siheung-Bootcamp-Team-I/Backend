//go:build windows

package main

import (
	"log/slog"

	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/event"
	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/runtime"
	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/sensor"
	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/transport"
)

// platformSensors 는 Windows 에서 돌릴 센서를 고른다.
//
// 프로세스, 네트워크, 파일을 ETW 세션 하나로 전부 받는다. 그래서 연결 이벤트의 PID 를
// 프로세스 이벤트와 같은 자리에서 이어 붙일 수 있다. Zeek 로는 못 하던 일이다.
func platformSensors(factory event.Factory, cfg transport.ServerConfig, _ *slog.Logger) []runtime.Sensor {
	return []runtime.Sensor{&sensor.ETWSensor{
		Factory:    factory,
		WatchPaths: cfg.WatchPaths,
		Sensors:    cfg.Sensors,
	}}
}
