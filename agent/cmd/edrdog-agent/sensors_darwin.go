//go:build darwin

package main

import (
	"log/slog"

	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/event"
	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/packet"
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
			// 해시기는 이 센서만 쓴다. 실행 이미지에만 해시를 붙이기 때문이다(eslFileEvent 주석).
			Hasher: sensor.NewFileHasher(),
		})
	}
	if cfg.Enabled("network") {
		sensors = append(sensors, &sensor.NetSnapSensor{Factory: factory})
	}
	if cfg.Enabled("dns") || cfg.Enabled("l7") {
		sensors = appendL7Sensor(sensors, factory, log)
	}
	return sensors
}

// appendL7Sensor 는 패킷 캡처 센서를 붙인다. 캡처를 못 열면 붙이지 않는다.
//
// 여기서 에이전트를 죽이지 않는 이유는 나머지 센서가 멀쩡하기 때문이다. 캡처는 root 와
// 이더넷 인터페이스를 요구해서 못 여는 상황이 흔한데, 그때 프로세스와 파일 관측까지 같이
// 잃으면 손해가 더 크다. 대신 왜 못 열었는지는 반드시 로그에 남긴다. 조용히 0건이 되면
// 캡처가 도는 줄 알고 없는 이벤트를 기다리게 된다.
func appendL7Sensor(sensors []runtime.Sensor, factory event.Factory, log *slog.Logger) []runtime.Sensor {
	capture, err := sensor.OpenCapture(log)
	if err != nil {
		log.Error("패킷 캡처를 열지 못해 dns/l7 수집을 건너뛴다", "err", err)
		return sensors
	}
	return append(sensors, &sensor.L7Sensor{
		Factory: factory,
		Source:  capture,
		// DNS 에는 프로세스를 붙이지 않는다. 그 이유는 L7Sensor.dnsEvent 주석에 적었다.
		Owner:    sensor.NewProcOwner(),
		LinkType: packet.LinkEthernet,
		Logger:   log,
	})
}
