package com.edrdog.apiservice.agent.web;

import com.edrdog.apiservice.agent.AgentService;
import com.edrdog.apiservice.agent.SensorConfig;
import com.edrdog.apiservice.agent.domain.AgentNode;
import com.edrdog.apiservice.auth.exception.AuthException;
import com.edrdog.apiservice.responder.ResponderClient;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 에이전트 수집 API(enroll/heartbeat/events/command-result). 프론트 X-API-Key 가 아니라
 * 자체 enroll_secret/node_key 로 인증하므로 ApiKeyFilter 예외 경로다.
 *
 * <p>인증 실패는 전부 HTTP 401 이다. 200 본문에 실패를 담지 않는다. 에이전트는 401 을 받으면
 * 저장한 node_key 를 버리고 다시 등록한 뒤 한 번 재시도한다. 서버가 재시작해 키를 잃어도
 * 사람이 손대지 않고 복구되어야 하기 때문이다.
 */
@RestController
@RequestMapping("/api/agent")
@Tag(name = "agent", description = "에이전트 수집 API (enroll/heartbeat/events/command-result)")
public class AgentController {

    private static final String NODE_KEY_HEADER = "X-Node-Key";

    private final AgentService service;
    private final ResponderClient responder;

    public AgentController(AgentService service, ResponderClient responder) {
        this.service = service;
        this.responder = responder;
    }

    @Operation(summary = "enroll", description = "enroll_secret(테넌트) 검증 후 node_key 를 발급한다. 실패 시 401.")
    @PostMapping("/enroll")
    public EnrollResponse enroll(@RequestBody EnrollRequest req) {
        String nodeKey = service.enroll(req.enrollSecret(), req.hostIdentifier(), req.platform())
                .orElseThrow(() -> AuthException.unauthorized("invalid_enroll_secret"));
        return new EnrollResponse(nodeKey);
    }

    @Operation(summary = "heartbeat", description = "node_key 인증 후 수집 설정과 대기 중인 대응 명령을 응답한다. 마지막 접속 시각도 갱신한다.")
    @PostMapping("/heartbeat")
    public HeartbeatResponse heartbeat(
            @RequestHeader(name = NODE_KEY_HEADER, required = false) String nodeKey) {
        AgentNode node = authenticate(nodeKey);
        return new HeartbeatResponse(
                SensorConfig.forPlatform(node.getPlatform()),
                responder.pendingCommands(node.getHostIdentifier()));
    }

    @Operation(summary = "events", description = "node_key 인증 후 이벤트에 tenant 를 태깅해 events-raw 로 발행한다.")
    @PostMapping("/events")
    public EventsResponse events(
            @RequestHeader(name = NODE_KEY_HEADER, required = false) String nodeKey,
            @RequestBody EventsRequest req) {
        AgentNode node = authenticate(nodeKey);
        return new EventsResponse(service.publish(node, req.events()));
    }

    @Operation(summary = "command-result", description = "node_key 인증 후 명령 실행 결과를 responder 로 전달한다.")
    @PostMapping("/command-result")
    public void commandResult(
            @RequestHeader(name = NODE_KEY_HEADER, required = false) String nodeKey,
            @RequestBody CommandResultRequest req) {
        authenticate(nodeKey);
        responder.reportCommandResult(req.commandId(), req.status(), req.message());
    }

    /** node_key 를 풀어 노드를 돌려준다. 유효하지 않으면 401(AuthExceptionHandler 가 매핑). */
    private AgentNode authenticate(String nodeKey) {
        return service.authenticate(nodeKey)
                .orElseThrow(() -> AuthException.unauthorized("invalid_node_key"));
    }
}
