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

// platformSensors 는 Windows 에서 돌릴 센서를 고른다.
//
// 프로세스, 네트워크, 파일, DNS 를 ETW 세션 하나로 전부 받는다. 그래서 연결 이벤트의 PID 를
// 프로세스 이벤트와 같은 자리에서 이어 붙일 수 있다. Zeek 로는 못 하던 일이다.
//
// TLS SNI 만 패킷을 봐야 하는데, 그 패킷도 같은 ETW 세션으로 올라온다(pktmon 프로바이더).
// 그래서 센서는 둘이지만 세션은 하나다.
func platformSensors(factory event.Factory, cfg transport.ServerConfig, log *slog.Logger) []runtime.Sensor {
	etwSensor := &sensor.ETWSensor{
		Factory:    factory,
		WatchPaths: cfg.WatchPaths,
		Sensors:    cfg.Sensors,
		Logger:     log,
	}
	sensors := []runtime.Sensor{etwSensor}

	if cfg.Enabled("l7") {
		sensors = appendL7Sensor(sensors, etwSensor, factory, log)
	}
	return sensors
}

// appendL7Sensor 는 TLS SNI 센서를 붙인다. 캡처를 못 열면 붙이지 않는다.
//
// 여기서 에이전트를 죽이지 않는 이유는 나머지 센서가 멀쩡하기 때문이다. pktmon 은 관리자
// 권한을 요구하고, 시스템 전체에 캡처 세션이 하나뿐이라 다른 도구가 쓰고 있으면 못 연다.
// 그때 프로세스와 파일 관측까지 같이 잃으면 손해가 더 크다. 대신 왜 못 열었는지는 반드시
// 로그에 남긴다. 조용히 0건이 되면 캡처가 도는 줄 알고 없는 이벤트를 기다리게 된다.
// macOS 쪽 appendL7Sensor 와 같은 판단이다.
//
// **dns 스위치는 보지 않는다.** Windows 의 DNS 는 이미 ETW 의 DNS-Client 프로바이더로 받고
// 있어서, 패킷에서 또 뽑으면 같은 질의가 두 번 올라간다. L7Sensor 는 UDP 53 을 보면 dns
// 이벤트를 내도록 되어 있으므로 그 경로가 아예 안 타게 막아야 하는데, 막는 자리는 커널
// 필터다. pktmon 필터를 TCP 443 하나만 걸어서 UDP 53 프레임은 애초에 올라오지 않는다
// (pktMonFilterArgs). 시작할 때 남아 있던 필터를 전부 지우고 우리 것만 거는 것도 같은 이유다.
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
		// 캡처가 이더넷 프레임으로 맞춰서 넘긴다. pktmon 은 프레임마다 이더넷인지 IP 헤더부터인지
		// 알려 주는데, 그 판단을 캡처 쪽에서 흡수해 센서는 한 가지 모양만 보게 했다.
		// 자세한 이유는 pktMonEthernetFrame 주석에 있다.
		LinkType: packet.LinkEthernet,
		Logger:   log,
	})
}
