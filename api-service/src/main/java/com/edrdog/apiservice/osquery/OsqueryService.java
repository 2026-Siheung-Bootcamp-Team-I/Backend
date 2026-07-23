package com.edrdog.apiservice.osquery;

import com.edrdog.apiservice.auth.domain.Tenant;
import com.edrdog.apiservice.auth.repository.TenantRepository;
import com.edrdog.apiservice.osquery.domain.OsqueryNode;
import com.edrdog.apiservice.osquery.repository.OsqueryNodeRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

/**
 * osquery TLS remote 3종의 서버 로직. enroll secret/node_key 인증과 tenant 태깅을 담당하고,
 * 태깅·정규화 규칙 같은 순수 판단은 {@link RawLogTagger} 에 위임한다.
 */
@Service
public class OsqueryService {

    private final TenantRepository tenants;
    private final OsqueryNodeRepository nodes;
    private final EventsRawProducer producer;
    private final ObjectMapper mapper = new ObjectMapper();

    public OsqueryService(TenantRepository tenants, OsqueryNodeRepository nodes, EventsRawProducer producer) {
        this.tenants = tenants;
        this.nodes = nodes;
        this.producer = producer;
    }

    /**
     * enroll secret 을 검증해 node_key 를 발급한다. 같은 tenant·host 재-enroll 은 기존 노드를 재사용한다.
     * 시크릿이 비었거나 매칭 tenant 가 없으면 빈 Optional(=node_invalid).
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
        OsqueryNode node = nodes.findByTenantIdAndHostIdentifier(tenant.getId(), host)
                .orElseGet(() -> OsqueryNode.enroll(OsqueryTokens.newToken(), tenant.getId(), host, platform, now));
        node.touch(now);
        nodes.save(node);
        return Optional.of(node.getNodeKey());
    }

    /** node_key 가 유효하면 수집 설정을 응답. 유효하지 않으면 빈 Optional(=node_invalid). */
    @Transactional
    public Optional<String> config(String nodeKey) {
        return resolve(nodeKey).map(node -> OsqueryConfig.SCHEDULE_JSON);
    }

    /**
     * node_key 로 tenant 를 풀어 각 result-log 를 태깅 후 events-raw 로 발행한다.
     * 유효하지 않은 node_key 면 false(=node_invalid). status 로그 등 result 가 아닌 data 는 조용히 무시.
     */
    @Transactional
    public boolean log(String nodeKey, JsonNode data) {
        Optional<OsqueryNode> found = resolve(nodeKey);
        if (found.isEmpty()) {
            return false;
        }
        OsqueryNode node = found.get();
        String tenantId = String.valueOf(node.getTenantId());
        for (String raw : RawLogTagger.tag(tenantId, data, mapper)) {
            producer.publish(node.getHostIdentifier(), raw);
        }
        return true;
    }

    /** node_key 로 노드를 찾고 마지막 관측 시각을 갱신. */
    private Optional<OsqueryNode> resolve(String nodeKey) {
        if (nodeKey == null || nodeKey.isBlank()) {
            return Optional.empty();
        }
        Optional<OsqueryNode> node = nodes.findById(nodeKey);
        node.ifPresent(n -> n.touch(Instant.now()));
        return node;
    }
}
