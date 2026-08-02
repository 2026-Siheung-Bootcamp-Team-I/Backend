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
            "/api/auth/",
            "/api/events",  // 조회는 세션 Bearer 로 인증하고 tenant 를 뽑는다(EventQueryController)
            "/api/alerts",  // 알림 조회·트리아지도 세션 Bearer 로 인증(AlertController)
            "/api/hosts",   // 호스트 목록·요약도 세션 Bearer 로 인증(HostController)
            "/api/operations",  // 파이프라인 상태 조회도 세션 Bearer 로 인증(OperationsHealthController)
            "/api/intelligence",  // 관계 분석 조회도 세션 Bearer 로 인증(intelligence 패키지 컨트롤러들)
            "/api/incidents",  // 사건 조회·트리아지도 세션 Bearer 로 인증(IncidentController)
            "/api/search",  // 통합 검색도 세션 Bearer 로 인증(SearchController)
            "/api/me",      // 유저 개인 알림 설정도 세션 Bearer 로 인증(UserNotifyController)
            "/api/demo/",   // 발표용 데모 시연도 세션 Bearer 로 인증하고 데모 계정만 통과시킨다(DemoController)
            "/api/internal/",  // 서비스 간 조회는 별도 X-Internal-Key 로 인증(TenantController), 프론트 키와 분리
            "/i/"          // 설치 스크립트 배포. curl 한 줄이라 헤더를 못 붙이고, 링크의 설치 토큰 자체가 인증이다.
    );

    /** 정확한 일치만 예외. 접두어로 열면 {@code /api/tenant} 아래 만료 없는 enroll secret 까지 딸려 열린다. */
    private static final List<String> EXEMPT_PATHS = List.of(
            // Bearer 로 이미 인증한다. API 키까지 요구하면 기기 하나 추가하려고 키를 두 개 쥐어야 한다.
            "/api/tenant/install-link"
    );

    private final String configuredKey;

    public ApiKeyPolicy(String configuredKey) {
        this.configuredKey = configuredKey;
    }

    /** CORS preflight 여부. preflight 에는 X-API-Key 가 안 붙어, 여기서 막으면 본 요청이 아예 발사되지 않는다. */
    public static boolean isPreflight(String method, String origin, String requestMethodHeader) {
        return "OPTIONS".equalsIgnoreCase(method) && origin != null && requestMethodHeader != null;
    }

    public boolean isExempt(String path) {
        return EXEMPT_PATHS.contains(path) || EXEMPT_PREFIXES.stream().anyMatch(path::startsWith);
    }

    public boolean isAuthorized(String providedKey) {
        return providedKey != null && !providedKey.isBlank() && configuredKey.equals(providedKey);
    }
}
