package com.edrdog.collectorservice.agent;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.util.Optional;

/**
 * enroll secret 을 tenant 로 바꿔 주는 api-service 내부 엔드포인트 호출
 * ({@code POST {base}/api/internal/agent/resolve-tenant}, 헤더 {@code X-Internal-Key}).
 * enroll 한 번에만 물어본다. heartbeat/events 는 node_key 로 끝나 이 호출이 낄 자리가 아니다.
 */
@Component
public class TenantResolverClient {

    private static final Logger log = LoggerFactory.getLogger(TenantResolverClient.class);

    private final RestClient http;
    private final String internalKey;

    public TenantResolverClient(@Value("${edrdog.api.url}") String baseUrl,
                                @Value("${edrdog.internal.key}") String internalKey) {
        this.http = RestClient.builder().baseUrl(baseUrl).build();
        this.internalKey = internalKey;
    }

    /** secret 에 맞는 tenant. 매칭 없음(404)이나 호출 실패면 empty(컨트롤러가 401 로 매핑). */
    public Optional<Long> resolve(String enrollSecret) {
        try {
            TenantResponse resp = http.post()
                    .uri("/api/internal/agent/resolve-tenant")
                    .contentType(MediaType.APPLICATION_JSON)
                    .header("X-Internal-Key", internalKey)
                    .body(new ResolveRequest(enrollSecret))
                    .retrieve()
                    .body(TenantResponse.class);
            return resp == null ? Optional.empty() : Optional.ofNullable(resp.tenantId());
        } catch (HttpClientErrorException.NotFound e) {
            return Optional.empty();   // 어느 조직과도 맞지 않는 secret
        } catch (RestClientException e) {
            log.error("tenant 조회 실패 err={}", e.toString());
            return Optional.empty();
        }
    }

    /** 요청 본문. secret 을 쿼리스트링에 싣지 않으려고 POST 로 보낸다(접근 로그에 남는다). */
    record ResolveRequest(String enrollSecret) {
    }

    /** 응답 스키마. 여분 필드는 무시. */
    record TenantResponse(Long tenantId) {
    }
}
