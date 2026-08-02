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
 *
 * <p>agent_nodes 테이블 소유가 collector 로 넘어가 api-service 는 DB 대신 HTTP 로 읽는다.
 * collector 는 클러스터 내부(ClusterIP)로만 노출되고, 서비스 간 인증은 X-Internal-Key 로 한다.
 * 다른 내부 RestClient(ClickHouseReader/ResponderClient)와 같은 per-component builder 패턴을 따른다.
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
     *
     * <p>collector 가 죽어 있거나 오류를 주면 빈 목록으로 답한다. 등록 기기 정보를 못 받는 것보다
     * 호스트 목록 화면 전체가 500 으로 죽는 쪽이 더 나쁘다(관측된 호스트는 ClickHouse 만으로도 보인다).
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
