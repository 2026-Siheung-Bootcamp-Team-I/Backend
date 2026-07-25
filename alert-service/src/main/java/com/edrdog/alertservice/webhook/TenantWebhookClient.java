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
 * api-service 내부 엔드포인트로 tenant 별 Slack webhook 을 조회한다 (API 컴포지션).
 * {@code GET {base}/api/internal/tenants/{tenantId}/webhook}, 헤더 {@code X-Internal-Key}.
 * 확정 결과(200 또는 404 미등록)만 짧은 TTL 로 캐시한다. 일시 조회 오류(api-service 다운 등)는
 * 캐시하지 않아 다음 alert 때 재시도되도록 한다(오류를 미등록으로 굳혀 알림을 유실시키지 않기 위함).
 */
@Component
public class TenantWebhookClient {

    private static final Logger log = LoggerFactory.getLogger(TenantWebhookClient.class);

    private final RestClient client;
    private final String internalKey;
    private final long ttlMs;
    private final Map<String, Cached> cache = new ConcurrentHashMap<>();

    public TenantWebhookClient(
            RestClient.Builder builder,
            @Value("${edrdog.api.base-url:http://localhost:8084}") String baseUrl,
            @Value("${edrdog.internal.key:dev-internal-key}") String internalKey,
            @Value("${edrdog.api.webhook-cache-ttl-ms:60000}") long ttlMs) {
        this.client = builder.baseUrl(baseUrl).build();
        this.internalKey = internalKey;
        this.ttlMs = ttlMs;
    }

    /** tenantId 의 webhook 을 조회. 미등록은 empty. 확정 결과만 TTL 캐시, 일시 오류는 캐시 안 함(재시도). */
    public Optional<String> resolve(String tenantId) {
        if (tenantId == null || tenantId.isBlank()) {
            return Optional.empty();
        }
        long now = System.currentTimeMillis();
        Cached cached = cache.get(tenantId);
        if (cached != null && now - cached.at() < ttlMs) {
            return cached.value();
        }
        Fetched fetched = fetch(tenantId);
        if (fetched.cacheable()) {
            cache.put(tenantId, new Cached(fetched.value(), now));
        }
        return fetched.value();
    }

    private Fetched fetch(String tenantId) {
        try {
            WebhookResponse resp = client.get()
                    .uri("/api/internal/tenants/{tenantId}/webhook", tenantId)
                    .header("X-Internal-Key", internalKey)
                    .retrieve()
                    .body(WebhookResponse.class);
            return new Fetched(toWebhook(resp), true);        // 200 → 확정, 캐시
        } catch (HttpClientErrorException.NotFound e) {
            return new Fetched(Optional.empty(), true);       // 404 → 미등록 확정, 캐시
        } catch (Exception e) {
            log.warn("tenant webhook 조회 실패 (일시 오류로 보고 캐시 안 함) tenantId={}: {}", tenantId, e.getMessage());
            return new Fetched(Optional.empty(), false);      // 일시 오류 → 캐시 안 함(다음에 재시도)
        }
    }

    /** 응답 → webhook. 응답이 없거나 webhookUrl 이 비면 미등록(empty). */
    static Optional<String> toWebhook(WebhookResponse resp) {
        if (resp == null || resp.webhookUrl() == null || resp.webhookUrl().isBlank()) {
            return Optional.empty();
        }
        return Optional.of(resp.webhookUrl());
    }

    /** 내부 엔드포인트 응답 스키마. 여분 필드는 무시. */
    public record WebhookResponse(Long tenantId, String webhookUrl) {
    }

    private record Cached(Optional<String> value, long at) {
    }

    /** 조회 결과 + 캐시 가능 여부(확정 결과만 true). */
    private record Fetched(Optional<String> value, boolean cacheable) {
    }
}
