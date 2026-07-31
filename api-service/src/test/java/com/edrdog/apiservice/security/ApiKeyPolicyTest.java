package com.edrdog.apiservice.security;

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
    void events_조회는_세션_Bearer_로_보호되므로_API키_예외() {
        assertTrue(policy.isExempt("/api/events"));
        assertTrue(policy.isExempt("/api/events/summary"));
    }

    @Test
    void alerts_hosts_조회도_세션_Bearer_예외() {
        assertTrue(policy.isExempt("/api/alerts"));
        assertTrue(policy.isExempt("/api/hosts"));
        assertTrue(policy.isExempt("/api/hosts/summary"));
    }

    @Test
    void 에이전트_수집은_자체_인증이므로_API키_예외() {
        assertTrue(policy.isExempt("/api/agent/enroll"));
        assertTrue(policy.isExempt("/api/agent/heartbeat"));
        assertTrue(policy.isExempt("/api/agent/events"));
        assertTrue(policy.isExempt("/api/agent/command-result"));
    }

    @Test
    void 설치_링크_발급은_세션_Bearer_예외() {
        // 호출자는 이미 Bearer 로 인증된 대시보드뿐이라 API 키까지 요구하면 키 두 개를 들어야 한다.
        assertTrue(policy.isExempt("/api/tenant/install-link"));
    }

    @Test
    void 나머지_tenant_경로는_여전히_API키가_필요하다() {
        // enroll secret·webhook 은 한 번 새면 되돌릴 수 없는 자격증명이라 문을 더 좁게 둔다.
        assertFalse(policy.isExempt("/api/tenant/enroll-secret"));
        assertFalse(policy.isExempt("/api/tenant/webhook"));
    }

    @Test
    void 설치_링크_접두어만_같은_경로는_예외가_아님() {
        assertFalse(policy.isExempt("/api/tenant/install-links-all"));
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

    @Test
    void CORS_preflight_는_키_없이도_통과_대상이다() {
        assertTrue(ApiKeyPolicy.isPreflight("OPTIONS", "http://localhost:5173", "POST"));
        assertTrue(ApiKeyPolicy.isPreflight("options", "https://edrdog.example", "GET"));
    }

    @Test
    void preflight_헤더가_빠진_OPTIONS_는_preflight_가_아니다() {
        assertFalse(ApiKeyPolicy.isPreflight("OPTIONS", null, "POST"));
        assertFalse(ApiKeyPolicy.isPreflight("OPTIONS", "http://localhost:5173", null));
        assertFalse(ApiKeyPolicy.isPreflight("POST", "http://localhost:5173", "POST"));
    }
}
