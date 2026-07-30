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
        // 이걸 부르는 건 대시보드(또는 그 대신 쓰는 스크립트)뿐이고 Bearer 로 이미 인증한다.
        // API 키까지 요구하면 기기 하나 추가하려고 사람이 키 두 개를 손에 쥐어야 한다.
        // 설치하는 사람에게서 키를 없애 놓고 만드는 사람에게 남겨 두면 절반만 한 것이다.
        assertTrue(policy.isExempt("/api/tenant/install-link"));
    }

    @Test
    void 나머지_tenant_경로는_여전히_API키가_필요하다() {
        // enroll secret 은 그 자체가 배포 자격증명이고 webhook 은 알림이 나가는 곳이다.
        // 설치 링크와 달리 한 번 새면 되돌릴 방법이 마땅치 않아 문을 더 좁게 둔다.
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
