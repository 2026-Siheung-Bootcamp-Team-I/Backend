package com.edrdog.apiservice.tenant;

import com.edrdog.apiservice.auth.domain.Tenant;
import com.edrdog.apiservice.auth.exception.AuthException;
import com.edrdog.apiservice.auth.repository.TenantRepository;
import com.edrdog.apiservice.security.Tokens;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

/**
 * tenant 의 Slack webhook 등록/조회. TenantRepository(auth) 를 재사용한다.
 * 검증 실패 400, tenant 없음 404 는 AuthException 으로 던져 전역 핸들러가 매핑한다.
 */
@Service
public class TenantService {

    private final TenantRepository tenants;

    public TenantService(TenantRepository tenants) {
        this.tenants = tenants;
    }

    @Transactional
    public void setWebhook(Long tenantId, String url) {
        if (!WebhookValidation.valid(url)) {
            throw AuthException.invalidInput("webhook URL 은 https:// 로 시작해야 합니다");
        }
        Tenant tenant = tenants.findById(tenantId)
                .orElseThrow(() -> AuthException.notFound("tenant 를 찾을 수 없습니다"));
        tenant.updateWebhook(url);
        tenants.save(tenant);
    }

    @Transactional(readOnly = true)
    public Optional<String> getWebhook(Long tenantId) {
        Tenant tenant = tenants.findById(tenantId)
                .orElseThrow(() -> AuthException.notFound("tenant 를 찾을 수 없습니다"));
        return Optional.ofNullable(tenant.getSlackWebhookUrl());
    }

    /**
     * enroll secret 이 가리키는 tenant PK. 매칭이 없거나 시크릿이 비면 empty(컨트롤러가 404 로 매핑).
     * collector 가 에이전트 enroll 을 받을 때만 부른다(tenants 테이블은 api-service 소유로 남는다).
     */
    @Transactional(readOnly = true)
    public Optional<Long> resolveTenant(String enrollSecret) {
        if (enrollSecret == null || enrollSecret.isBlank()) {
            return Optional.empty();
        }
        return tenants.findByEnrollSecret(enrollSecret).map(Tenant::getId);
    }

    /** enroll secret 을 새로 발급해 기존 값을 덮는다. 이전 시크릿으로는 더 이상 enroll 되지 않는다. */
    @Transactional
    public String rotateEnrollSecret(Long tenantId) {
        Tenant tenant = tenants.findById(tenantId)
                .orElseThrow(() -> AuthException.notFound("tenant 를 찾을 수 없습니다"));
        String secret = Tokens.newToken();
        tenant.updateEnrollSecret(secret);
        tenants.save(tenant);
        return secret;
    }

    /** 현재 enroll secret 조회. 없으면 그 자리에서 발급한다. tenant 없음 404. */
    @Transactional
    public Optional<String> getEnrollSecret(Long tenantId) {
        Tenant tenant = tenants.findById(tenantId)
                .orElseThrow(() -> AuthException.notFound("tenant 를 찾을 수 없습니다"));
        // 없을 때만 만든다. 조회마다 바뀌면 이미 배포한 기기의 안내가 어긋난다.
        if (tenant.getEnrollSecret() == null) {
            tenant.updateEnrollSecret(Tokens.newToken());
            tenants.save(tenant);
        }
        return Optional.of(tenant.getEnrollSecret());
    }
}
