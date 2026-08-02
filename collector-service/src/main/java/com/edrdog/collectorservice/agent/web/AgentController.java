package com.edrdog.collectorservice.agent.web;

import com.edrdog.collectorservice.agent.AgentService;
import com.edrdog.collectorservice.agent.SensorConfig;
import com.edrdog.collectorservice.agent.domain.AgentNode;
import com.edrdog.collectorservice.agent.exception.AuthException;
import com.edrdog.collectorservice.responder.ResponderClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 에이전트 수집 API(enroll/heartbeat/events/command-result). 자체 enroll_secret/node_key 로 인증한다.
 *
 * <p>인증 실패는 전부 HTTP 401 이다. 200 본문에 실패를 담지 않는다. 에이전트는 401 을 받으면
 * 저장한 node_key 를 버리고 다시 등록한 뒤 한 번 재시도한다. 서버가 재시작해 키를 잃어도
 * 사람이 손대지 않고 복구되어야 하기 때문이다.
 *
 * <p>node_key 는 해시로만 저장한다. 이전에 api-service 가 평문으로 발급해 둔 키는 여기서 인증되지
 * 않지만 마이그레이션은 필요 없다. 그 에이전트는 401 을 받고 스스로 다시 등록한다.
 */
@RestController
@RequestMapping("/api/agent")
public class AgentController {

    private static final String NODE_KEY_HEADER = "X-Node-Key";

    private final AgentService service;
    private final ResponderClient responder;

    public AgentController(AgentService service, ResponderClient responder) {
        this.service = service;
        this.responder = responder;
    }

    @PostMapping("/enroll")
    public EnrollResponse enroll(@RequestBody EnrollRequest req) {
        String nodeKey = service.enroll(req.enrollSecret(), req.hostIdentifier(), req.platform())
                .orElseThrow(() -> AuthException.unauthorized("invalid_enroll_secret"));
        return new EnrollResponse(nodeKey);
    }

    @PostMapping("/heartbeat")
    public HeartbeatResponse heartbeat(
            @RequestHeader(name = NODE_KEY_HEADER, required = false) String nodeKey) {
        AgentNode node = authenticate(nodeKey);
        return new HeartbeatResponse(
                SensorConfig.forPlatform(node.getPlatform()),
                responder.pendingCommands(node.getHostIdentifier()));
    }

    @PostMapping("/events")
    public EventsResponse events(
            @RequestHeader(name = NODE_KEY_HEADER, required = false) String nodeKey,
            @RequestBody EventsRequest req) {
        AgentNode node = authenticate(nodeKey);
        return new EventsResponse(service.publish(node, req.events()));
    }

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
