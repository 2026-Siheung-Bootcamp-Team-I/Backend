package com.edrdog.apiservice.collector;

import com.edrdog.apiservice.host.EnrolledHost;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.util.Arrays;
import java.util.List;

/**
 * collector-service 내부 API 호출 래퍼(등록 노드 조회).
 * collector 는 클러스터 내부(ClusterIP)로만 노출되고, 서비스 간 인증은 X-Internal-Key 로 한다.
 */
@Component
public class CollectorClient {

    private static final Logger log = LoggerFactory.getLogger(CollectorClient.class);

    private final RestClient http;
    private final String internalKey;

    public CollectorClient(@Value("${edrdog.collector.url}") String baseUrl,
                           @Value("${edrdog.internal.key}") String internalKey) {
        this.internalKey = internalKey;
        this.http = RestClient.builder().baseUrl(baseUrl).build();
    }

    /**
     * tenant 에 등록된 노드 목록(host/마지막 접속 시각/OS).
     * collector 오류를 빈 목록으로 삼킨다. 올려보내면 호스트 목록 화면 전체가 500 으로 죽는다.
     */
    public List<EnrolledHost> enrolledHosts(long tenantId) {
        try {
            Node[] nodes = http.get()
                    .uri(uri -> uri.path("/api/internal/nodes").queryParam("tenantId", tenantId).build())
                    .header("X-Internal-Key", internalKey)
                    .retrieve()
                    .body(Node[].class);
            return nodes == null ? List.of() : Arrays.stream(nodes).map(Node::toEnrolledHost).toList();
        } catch (RestClientException e) {
            log.warn("collector 등록 노드 조회 실패 tenantId={} err={}", tenantId, e.toString());
            return List.of();
        }
    }

    /** collector 내부 API 응답 한 행(계약: host/lastSeenAt/platform). */
    record Node(String host, long lastSeenAt, String platform) {

        EnrolledHost toEnrolledHost() {
            return new EnrolledHost(host, lastSeenAt, platform);
        }
    }
}
