package com.edrdog.apiservice.tenant;

import com.edrdog.apiservice.auth.exception.AuthException;
import com.edrdog.apiservice.auth.service.AuthService;
import com.edrdog.apiservice.auth.service.Principal;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * tenant Slack webhook 등록/조회.
 * /api/tenant/** 은 로그인 유저가 자기 tenant 것만(Bearer + 프론트 X-API-Key),
 * /api/internal/** 은 서비스 간 조회로 별도 X-Internal-Key 로만 인증한다(프론트 키로는 열 수 없음 → tenant 열거 방지).
 */
@RestController
@Tag(name = "tenant", description = "tenant Slack webhook 등록/조회")
public class TenantController {

    private static final String BEARER_PREFIX = "Bearer ";

    private final TenantService tenants;
    private final AuthService auth;
    private final String internalKey;

    public TenantController(TenantService tenants, AuthService auth,
                            @Value("${edrdog.internal.key}") String internalKey) {
        this.tenants = tenants;
        this.auth = auth;
        this.internalKey = internalKey;
    }

    @Operation(summary = "webhook 등록", description = "로그인 유저(Bearer)의 tenant 에 Slack webhook URL 을 저장한다.")
    @PutMapping("/api/tenant/webhook")
    public WebhookResponse setWebhook(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @RequestBody WebhookRequest req) {
        Principal principal = auth.resolve(bearerToken(authorization));
        tenants.setWebhook(principal.tenantId(), req.webhookUrl());
        return new WebhookResponse(principal.tenantId(), req.webhookUrl());
    }

    @Operation(summary = "내 webhook 조회", description = "로그인 유저(Bearer)의 tenant 에 저장된 webhook URL 을 조회한다.")
    @GetMapping("/api/tenant/webhook")
    public WebhookResponse getWebhook(
            @RequestHeader(name = "Authorization", required = false) String authorization) {
        Principal principal = auth.resolve(bearerToken(authorization));
        String url = tenants.getWebhook(principal.tenantId()).orElse(null);
        return new WebhookResponse(principal.tenantId(), url);
    }

    @Operation(summary = "내부 webhook 조회", description = "서비스 간 조회용(X-Internal-Key). 지정 tenant 의 webhook URL 을 조회한다.")
    @GetMapping("/api/internal/tenants/{tenantId}/webhook")
    public WebhookResponse getWebhookInternal(
            @PathVariable Long tenantId,
            @RequestHeader(name = "X-Internal-Key", required = false) String internalKeyHeader) {
        if (internalKeyHeader == null || !internalKey.equals(internalKeyHeader)) {
            throw AuthException.unauthorized("유효한 X-Internal-Key 가 필요합니다");
        }
        String url = tenants.getWebhook(tenantId).orElse(null);
        return new WebhookResponse(tenantId, url);
    }

    /** "Bearer " 접두어를 떼서 토큰만 반환. 없으면 null. */
    private static String bearerToken(String authorization) {
        if (authorization == null || !authorization.startsWith(BEARER_PREFIX)) {
            return null;
        }
        return authorization.substring(BEARER_PREFIX.length()).trim();
    }
}
