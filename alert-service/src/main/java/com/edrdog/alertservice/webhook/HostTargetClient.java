package com.edrdog.alertservice.webhook;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * api-service 내부 엔드포인트로 host 소유 유저의 알림 목적지를 조회한다 (API 컴포지션).
 * {@code GET {base}/api/internal/alert-target?tenantId={}&host={}}, 헤더 {@code X-Internal-Key}.
 * {@link TenantWebhookClient} 와 같은 캐시 규칙: 확정 결과(200/404)만 짧은 TTL 로 캐시하고
 * 일시 오류(api-service 다운 등)는 캐시하지 않아 다음 alert 때 재시도한다.
 */
@Component
public class HostTargetClient {

    private static final Logger log = LoggerFactory.getLogger(HostTargetClient.class);

    private final RestClient client;
    private final String internalKey;
    private final long ttlMs;
    private final Map<String, Cached> cache = new ConcurrentHashMap<>();

    public HostTargetClient(
            RestClient.Builder builder,
            @Value("${edrdog.api.base-url:http://localhost:8084}") String baseUrl,
            @Value("${edrdog.internal.key:dev-internal-key}") String internalKey,
            @Value("${edrdog.api.webhook-cache-ttl-ms:60000}") long ttlMs) {
        this.client = builder.baseUrl(baseUrl).build();
        this.internalKey = internalKey;
        this.ttlMs = ttlMs;
    }

    /** tenantId+host 의 소유 목적지를 조회. 소유자 없음/미설정은 empty. 확정 결과만 TTL 캐시. */
    public Optional<Target> resolve(String tenantId, String host) {
        if (tenantId == null || tenantId.isBlank() || host == null || host.isBlank()) {
            return Optional.empty();
        }
        String key = tenantId + "|" + host;
        long now = System.currentTimeMillis();
        Cached cached = cache.get(key);
        if (cached != null && now - cached.at() < ttlMs) {
            return cached.value();
        }
        Fetched fetched = fetch(tenantId, host);
        if (fetched.cacheable()) {
            cache.put(key, new Cached(fetched.value(), now));
        }
        return fetched.value();
    }

    private Fetched fetch(String tenantId, String host) {
        try {
            TargetResponse resp = client.get()
                    .uri(uriBuilder -> uriBuilder.path("/api/internal/alert-target")
                            .queryParam("tenantId", tenantId)
                            .queryParam("host", host)
                            .build())
                    .header("X-Internal-Key", internalKey)
                    .retrieve()
                    .body(TargetResponse.class);
            return new Fetched(toTarget(resp), true);         // 200 → 확정, 캐시
        } catch (HttpClientErrorException.NotFound e) {
            return new Fetched(Optional.empty(), true);       // 404 → 소유자 없음 확정, 캐시
        } catch (Exception e) {
            log.warn("alert-target 조회 실패 (일시 오류로 보고 캐시 안 함) tenantId={} host={}: {}",
                    tenantId, host, e.getMessage());
            return new Fetched(Optional.empty(), false);      // 일시 오류 → 캐시 안 함(다음에 재시도)
        }
    }

    /** 응답 → Target. 응답이 없거나 webhookUrl 이 비면 미설정(empty). */
    static Optional<Target> toTarget(TargetResponse resp) {
        if (resp == null || resp.webhookUrl() == null || resp.webhookUrl().isBlank()) {
            return Optional.empty();
        }
        return Optional.of(new Target(resp.userId(), resp.webhookUrl()));
    }

    /** host 소유 유저의 목적지. */
    public record Target(Long userId, String webhookUrl) {
    }

    /** 내부 엔드포인트 응답 스키마. 여분 필드는 무시. */
    public record TargetResponse(Long userId, String webhookUrl) {
    }

    private record Cached(Optional<Target> value, long at) {
    }

    /** 조회 결과 + 캐시 가능 여부(확정 결과만 true). */
    private record Fetched(Optional<Target> value, boolean cacheable) {
    }
}
