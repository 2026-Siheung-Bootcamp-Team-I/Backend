package com.edrdog.apiservice.agent;

import com.edrdog.apiservice.agent.domain.AgentNode;
import com.edrdog.apiservice.agent.repository.AgentNodeRepository;
import com.edrdog.apiservice.auth.domain.Tenant;
import com.edrdog.apiservice.auth.repository.TenantRepository;
import com.edrdog.apiservice.security.Tokens;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

/**
 * 에이전트 수집 API 의 서버 로직. enroll secret/node_key 인증과 tenant 태깅을 담당하고,
 * 태깅 규칙 같은 순수 판단은 {@link EventTagger}, 설정 판단은 {@link SensorConfig} 에 위임한다.
 */
@Service
public class AgentService {

    private final TenantRepository tenants;
    private final AgentNodeRepository nodes;
    private final EventsRawProducer producer;
    private final ObjectMapper mapper = new ObjectMapper();

    public AgentService(TenantRepository tenants, AgentNodeRepository nodes, EventsRawProducer producer) {
        this.tenants = tenants;
        this.nodes = nodes;
        this.producer = producer;
    }

    /**
     * enroll secret 을 검증해 node_key 를 발급한다. 같은 tenant·host 재-enroll 은 기존 노드를 재사용한다.
     * 시크릿이 비었거나 매칭 tenant 가 없으면 빈 Optional(컨트롤러가 401 로 매핑).
     */
    @Transactional
    public Optional<String> enroll(String enrollSecret, String hostIdentifier, String platform) {
        if (enrollSecret == null || enrollSecret.isBlank()) {
            return Optional.empty();
        }
        Tenant tenant = tenants.findByEnrollSecret(enrollSecret).orElse(null);
        if (tenant == null) {
            return Optional.empty();
        }
        String host = (hostIdentifier == null || hostIdentifier.isBlank()) ? "unknown" : hostIdentifier;
        Instant now = Instant.now();
        AgentNode node = nodes.findByTenantIdAndHostIdentifier(tenant.getId(), host)
                .orElseGet(() -> AgentNode.enroll(Tokens.newToken(), tenant.getId(), host, platform, now));
        node.touch(now);
        nodes.save(node);
        return Optional.of(node.getNodeKey());
    }

    /**
     * node_key 로 노드를 찾고 마지막 관측 시각을 갱신한다. 인증이 필요한 엔드포인트가 전부 이걸 통과한다.
     * 유효하지 않으면 빈 Optional(컨트롤러가 401 로 매핑).
     */
    @Transactional
    public Optional<AgentNode> authenticate(String nodeKey) {
        if (nodeKey == null || nodeKey.isBlank()) {
            return Optional.empty();
        }
        Optional<AgentNode> node = nodes.findById(nodeKey);
        node.ifPresent(n -> n.touch(Instant.now()));
        return node;
    }

    /**
     * 이벤트 배열에 서버가 푼 tenantId 를 심어 events-raw 로 발행하고 받은 건수를 돌려준다.
     * 에이전트는 이 건수를 보고 배치를 버퍼에서 지운다.
     */
    public int publish(AgentNode node, JsonNode events) {
        String tenantId = String.valueOf(node.getTenantId());
        int accepted = 0;
        for (String raw : EventTagger.tag(tenantId, events, mapper)) {
            producer.publish(node.getHostIdentifier(), raw);
            accepted++;
        }
        return accepted;
    }
}
