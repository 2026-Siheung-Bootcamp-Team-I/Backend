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

    @Transactional
    public String rotateEnrollSecret(Long tenantId) {
        Tenant tenant = tenants.findById(tenantId)
                .orElseThrow(() -> AuthException.notFound("tenant 를 찾을 수 없습니다"));
        String secret = Tokens.newToken();
        tenant.updateEnrollSecret(secret);
        tenants.save(tenant);
        return secret;
    }

    /**
     * 현재 enroll secret 조회. 없으면 그 자리에서 발급한다. tenant 없음 404.
     *
     * <p>tenant 당 하나 있으면 되는 값인데 사용자가 버튼을 눌러야 생기는 구조였다. 그러면 온보딩의
     * 설치 명령이 빈 채로 보이고, 사용자는 왜 눌러야 하는지 알 수 없다. 조회 시점에 만들어 준다.
     * 이미 있으면 그대로 돌려준다(호출할 때마다 바뀌면 이미 배포한 기기의 안내가 어긋난다).
     * 값을 갈아치우는 건 명시적인 재발급(rotateEnrollSecret)만 한다.
     */
    @Transactional
    public Optional<String> getEnrollSecret(Long tenantId) {
        Tenant tenant = tenants.findById(tenantId)
                .orElseThrow(() -> AuthException.notFound("tenant 를 찾을 수 없습니다"));
        if (tenant.getEnrollSecret() == null) {
            tenant.updateEnrollSecret(Tokens.newToken());
            tenants.save(tenant);
        }
        return Optional.of(tenant.getEnrollSecret());
    }
}
