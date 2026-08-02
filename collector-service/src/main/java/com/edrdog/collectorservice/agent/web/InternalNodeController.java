package com.edrdog.collectorservice.agent.web;

import com.edrdog.collectorservice.agent.exception.AuthException;
import com.edrdog.collectorservice.agent.repository.AgentNodeRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * 등록 노드 조회(서비스 간). api-service 의 호스트 목록 화면이 조용한 노드를 채워 넣는 데 쓴다.
 * 프론트 키가 아니라 X-Internal-Key 로만 인증한다(다른 조직의 호스트 열거 방지).
 */
@RestController
public class InternalNodeController {

    private final AgentNodeRepository nodes;
    private final String internalKey;

    public InternalNodeController(AgentNodeRepository nodes,
                                  @Value("${edrdog.internal.key}") String internalKey) {
        this.nodes = nodes;
        this.internalKey = internalKey;
    }

    @GetMapping("/api/internal/nodes")
    public List<NodeView> nodes(@RequestParam(name = "tenantId", required = false) String tenantId,
                                @RequestHeader(name = "X-Internal-Key", required = false) String internalKeyHeader) {
        if (internalKeyHeader == null || !internalKey.equals(internalKeyHeader)) {
            throw AuthException.unauthorized("유효한 X-Internal-Key 가 필요합니다");
        }
        Long id = parseTenantId(tenantId);
        if (id == null) {
            return List.of();
        }
        return nodes.findByTenantId(id).stream()
                .map(n -> new NodeView(n.getHostIdentifier(), n.getLastSeenAt().toEpochMilli(), n.getPlatform()))
                .toList();
    }

    /** 숫자가 아니면 빈 결과로 답한다. 호출자 실수로 500 을 내면 호스트 목록 화면 전체가 죽는다. */
    private static Long parseTenantId(String tenantId) {
        try {
            return tenantId == null ? null : Long.valueOf(tenantId.trim());
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /** 등록 노드 1건. lastSeenAt 은 epoch millis. */
    public record NodeView(String host, long lastSeenAt, String platform) {
    }
}
