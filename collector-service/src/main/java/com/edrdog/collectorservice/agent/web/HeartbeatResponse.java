package com.edrdog.collectorservice.agent.web;

import com.edrdog.collectorservice.agent.SensorConfig;
import com.edrdog.collectorservice.responder.AgentCommand;

import java.util.List;

/**
 * 하트비트 응답. 설정과 대응 명령을 한 번에 내려준다.
 * 엔드포인트가 방화벽 안쪽이라 서버가 먼저 접속할 수 없어 명령을 여기 실어 보낸다.
 */
public record HeartbeatResponse(SensorConfig.Config config, List<AgentCommand> commands) {
}
