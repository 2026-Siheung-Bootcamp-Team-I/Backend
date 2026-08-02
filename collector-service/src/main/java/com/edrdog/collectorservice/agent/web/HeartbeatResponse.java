package com.edrdog.collectorservice.agent.web;

import com.edrdog.collectorservice.agent.SensorConfig;
import com.edrdog.collectorservice.responder.AgentCommand;

import java.util.List;

/**
 * 하트비트 응답. 설정과 대응 명령을 한 번에 내려준다.
 *
 * <p>대응 채널을 따로 열지 않는 이유는 엔드포인트가 방화벽 안쪽이라 서버가 먼저 접속할 수 없기 때문이다.
 * 에이전트가 주기적으로 물어보는 쪽이 설치 부담 없이 동작하는 유일한 방법이다.
 */
public record HeartbeatResponse(SensorConfig.Config config, List<AgentCommand> commands) {
}
