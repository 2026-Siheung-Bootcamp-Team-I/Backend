package com.edrdog.apiservice.security;

import java.util.List;

/**
 * API Key 인증 판단(순수). 인증 예외 경로 판별과 키 일치 여부만 담당한다.
 */
public class ApiKeyPolicy {

    private static final List<String> EXEMPT_PREFIXES = List.of(
            "/actuator/health",
            "/swagger-ui",
            "/v3/api-docs",
            "/api/auth/"
    );

    private final String configuredKey;

    public ApiKeyPolicy(String configuredKey) {
        this.configuredKey = configuredKey;
    }

    /** 헬스체크·Swagger 등 인증 없이 열어두는 경로. */
    public boolean isExempt(String path) {
        return EXEMPT_PREFIXES.stream().anyMatch(path::startsWith);
    }

    /** 제공된 키가 설정 키와 정확히 일치하면 통과. null/빈 값은 거부. */
    public boolean isAuthorized(String providedKey) {
        return providedKey != null && !providedKey.isBlank() && configuredKey.equals(providedKey);
    }
}
