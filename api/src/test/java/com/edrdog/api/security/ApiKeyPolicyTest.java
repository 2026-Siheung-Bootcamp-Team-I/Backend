package com.edrdog.api.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * API Key 인증의 판단 로직(순수): 어떤 경로가 인증 예외이고, 어떤 키가 통과인지.
 */
class ApiKeyPolicyTest {

    private final ApiKeyPolicy policy = new ApiKeyPolicy("secret-key");

    @Test
    void 헬스체크와_swagger_는_인증_예외() {
        assertTrue(policy.isExempt("/actuator/health"));
        assertTrue(policy.isExempt("/swagger-ui/index.html"));
        assertTrue(policy.isExempt("/swagger-ui.html"));
        assertTrue(policy.isExempt("/v3/api-docs"));
        assertTrue(policy.isExempt("/v3/api-docs/swagger-config"));
    }

    @Test
    void auth_엔드포인트는_인증_예외() {
        assertTrue(policy.isExempt("/api/auth/login"));
        assertTrue(policy.isExempt("/api/auth/signup"));
    }

    @Test
    void 일반_API_경로는_예외가_아님() {
        assertFalse(policy.isExempt("/api/events"));
        assertFalse(policy.isExempt("/api/events/summary"));
    }

    @Test
    void auth_접두어만_같은_경로는_예외가_아님() {
        assertFalse(policy.isExempt("/api/authz"));
        assertFalse(policy.isExempt("/api/auth-logs"));
    }

    @Test
    void 설정된_키와_일치하면_통과() {
        assertTrue(policy.isAuthorized("secret-key"));
    }

    @Test
    void 키가_틀리거나_없으면_거부() {
        assertFalse(policy.isAuthorized("wrong"));
        assertFalse(policy.isAuthorized(null));
        assertFalse(policy.isAuthorized(""));
        assertFalse(policy.isAuthorized("  "));
    }
}
