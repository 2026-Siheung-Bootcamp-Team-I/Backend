package com.edrdog.apiservice.tenant.web;

import com.edrdog.apiservice.auth.AuthException;
import com.edrdog.apiservice.auth.AuthService;
import com.edrdog.apiservice.auth.Principal;
import com.edrdog.apiservice.tenant.TenantService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * tenant Slack webhook·enroll secret 등록/조회.
 * /api/tenant/** 은 로그인 유저가 자기 tenant 것만(Bearer + 프론트 X-API-Key), /api/internal/** 은 서비스 간 조회다.
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

    @Operation(summary = "enroll secret 발급/회전", description = "로그인 유저(Bearer)의 tenant 에 enroll secret 을 새로 발급한다. 엔드포인트 에이전트 설정의 enroll_secret 에 넣는다.")
    @PostMapping("/api/tenant/enroll-secret")
    public EnrollSecretResponse rotateEnrollSecret(
            @RequestHeader(name = "Authorization", required = false) String authorization) {
        Principal principal = auth.resolve(bearerToken(authorization));
        String secret = tenants.rotateEnrollSecret(principal.tenantId());
        return new EnrollSecretResponse(principal.tenantId(), secret);
    }

    @Operation(summary = "내 enroll secret 조회", description = "로그인 유저(Bearer)의 tenant 에 발급된 enroll secret 을 조회한다. 미발급이면 null.")
    @GetMapping("/api/tenant/enroll-secret")
    public EnrollSecretResponse getEnrollSecret(
            @RequestHeader(name = "Authorization", required = false) String authorization) {
        Principal principal = auth.resolve(bearerToken(authorization));
        String secret = tenants.getEnrollSecret(principal.tenantId()).orElse(null);
        return new EnrollSecretResponse(principal.tenantId(), secret);
    }

    @Operation(summary = "내부 webhook 조회", description = "서비스 간 조회용(X-Internal-Key). 지정 tenant 의 webhook URL 을 조회한다.")
    @GetMapping("/api/internal/tenants/{tenantId}/webhook")
    public WebhookResponse getWebhookInternal(
            @PathVariable Long tenantId,
            @RequestHeader(name = "X-Internal-Key", required = false) String internalKeyHeader) {
        requireInternalKey(internalKeyHeader);
        String url = tenants.getWebhook(tenantId).orElse(null);
        return new WebhookResponse(tenantId, url);
    }

    @Operation(summary = "내부 enroll secret 검증",
            description = "collector 가 에이전트 enroll 을 받을 때 부른다(X-Internal-Key). 시크릿에 맞는 tenant 가 없으면 404.")
    @PostMapping("/api/internal/agent/resolve-tenant")
    public ResponseEntity<ResolveTenantResponse> resolveTenant(
            @RequestHeader(name = "X-Internal-Key", required = false) String internalKeyHeader,
            @RequestBody ResolveTenantRequest req) {
        requireInternalKey(internalKeyHeader);
        // 못 찾은 이유(시크릿이 빈 값인지 틀린 값인지)는 알려주지 않는다. 대입 시도에 힌트가 된다.
        return tenants.resolveTenant(req.enrollSecret())
                .map(id -> ResponseEntity.ok(new ResolveTenantResponse(id)))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    // 프론트 X-API-Key 와 분리된 별도 키다. 프론트 키로도 열면 아무 tenant 나 열거할 수 있게 된다.
    private void requireInternalKey(String internalKeyHeader) {
        if (internalKeyHeader == null || !internalKey.equals(internalKeyHeader)) {
            throw AuthException.unauthorized("유효한 X-Internal-Key 가 필요합니다");
        }
    }

    private static String bearerToken(String authorization) {
        if (authorization == null || !authorization.startsWith(BEARER_PREFIX)) {
            return null;
        }
        return authorization.substring(BEARER_PREFIX.length()).trim();
    }
}
