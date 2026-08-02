//go:build windows

package main

import (
	"log/slog"

	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/event"
	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/packet"
	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/runtime"
	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/sensor"
	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/transport"
)

// platformSensors 는 Windows 에서 돌릴 센서를 고른다. 프로세스/네트워크/파일/DNS 와 SNI 패킷까지 ETW 세션 하나로 받는다.
func platformSensors(factory event.Factory, cfg transport.ServerConfig, log *slog.Logger) []runtime.Sensor {
	etwSensor := &sensor.ETWSensor{
		Factory:    factory,
		WatchPaths: cfg.WatchPaths,
		Sensors:    cfg.Sensors,
		Logger:     log,
		// 해시기는 이 센서만 쓴다. 실행 이미지에만 해시를 붙이기 때문이다(MapFile 주석).
		Hasher: sensor.NewFileHasher(),
	}
	sensors := []runtime.Sensor{etwSensor}

	if cfg.Enabled("l7") {
		sensors = appendL7Sensor(sensors, etwSensor, factory, log)
	}
	return sensors
}

// appendL7Sensor 는 TLS SNI 센서를 붙인다. 캡처를 못 열면 나머지 센서를 살리려고 이것만 빼고 간다.
// dns 스위치는 보지 않는다. DNS 는 ETW 로 이미 받고 있어 패킷 쪽 경로는 pktmon 필터(TCP 443)로 막아 둔다.
func appendL7Sensor(sensors []runtime.Sensor, etwSensor *sensor.ETWSensor, factory event.Factory, log *slog.Logger) []runtime.Sensor {
	capture, err := sensor.OpenPktMonCapture(log)
	if err != nil {
		log.Error("pktmon 캡처를 열지 못해 l7 수집을 건너뛴다", "err", err)
		return sensors
	}

	// 같은 것을 양쪽에 넘긴다. ETW 쪽이 연결 이벤트로 채우고 L7 쪽이 SNI 를 볼 때 꺼내 쓴다.
	flows := sensor.NewFlowOwners()
	etwSensor.PktMon = capture
	etwSensor.Flows = flows

	return append(sensors, &sensor.L7Sensor{
		Factory: factory,
		Source:  capture,
		Owner:   flows,
		// 캡처가 이더넷 프레임으로 맞춰서 넘긴다(pktMonEthernetFrame 주석).
		LinkType: packet.LinkEthernet,
		Logger:   log,
	})
}
