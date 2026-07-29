//go:build darwin

package main

import (
	"log/slog"

	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/event"
	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/runtime"
	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/sensor"
	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/transport"
)

// platformSensors 는 macOS 에서 돌릴 센서를 고른다.
//
// 프로세스와 파일은 eslogger 로 EndpointSecurity 이벤트를 받고, 네트워크만 스냅샷으로 훑는다.
// EndpointSecurity API 에 소켓 연결 이벤트가 없어서 그렇다. 이 프로젝트에서 유일한 폴링이다.
func platformSensors(factory event.Factory, cfg transport.ServerConfig, log *slog.Logger) []runtime.Sensor {
	var sensors []runtime.Sensor

	if cfg.Enabled("process") || cfg.Enabled("file") {
		sensors = append(sensors, &sensor.ESLoggerSensor{
			Factory:    factory,
			WatchPaths: cfg.WatchPaths,
			Logger:     log,
		})
	}
	if cfg.Enabled("network") {
		sensors = append(sensors, &sensor.NetSnapSensor{Factory: factory})
	}
	return sensors
}
