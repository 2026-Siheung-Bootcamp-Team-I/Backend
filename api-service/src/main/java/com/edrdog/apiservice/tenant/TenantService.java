package com.edrdog.apiservice.tenant;

import com.edrdog.apiservice.auth.domain.Tenant;
import com.edrdog.apiservice.auth.exception.AuthException;
import com.edrdog.apiservice.auth.repository.TenantRepository;
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

    /** webhook 등록/갱신. URL 검증 실패 400, tenant 없음 404. */
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

    /** 현재 webhook 조회. tenant 없음 404, 미설정이면 빈 Optional. */
    @Transactional(readOnly = true)
    public Optional<String> getWebhook(Long tenantId) {
        Tenant tenant = tenants.findById(tenantId)
                .orElseThrow(() -> AuthException.notFound("tenant 를 찾을 수 없습니다"));
        return Optional.ofNullable(tenant.getSlackWebhookUrl());
    }
}
