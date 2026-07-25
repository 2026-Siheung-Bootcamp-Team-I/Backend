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
            "/api/me",      // 유저 개인 알림 설정도 세션 Bearer 로 인증(UserNotifyController)
            "/api/demo/",   // 발표용 데모 시연도 세션 Bearer 로 인증하고 데모 계정만 통과시킨다(DemoController)
            "/api/internal/",  // 서비스 간 조회는 별도 X-Internal-Key 로 인증(TenantController), 프론트 키와 분리
            "/api/osquery/"  // 엔드포인트 수집은 자체 enroll_secret/node_key 로 인증(OsqueryController), 프론트 키와 분리
    );

    private final String configuredKey;

    public ApiKeyPolicy(String configuredKey) {
        this.configuredKey = configuredKey;
    }

    /**
     * CORS preflight 여부. 브라우저는 preflight 에 커스텀 헤더(X-API-Key)를 싣지 않으므로
     * 여기서 막으면 본 요청이 아예 발사되지 않는다(프론트에는 "서버에 연결하지 못했습니다"로 보인다).
     * preflight 는 본문 없는 협상 요청이라 통과시켜도 데이터가 새지 않고, 실제 요청은 그대로 검사된다.
     * 판정은 브라우저가 붙이는 두 헤더의 존재로 한다(단순 OPTIONS 는 preflight 가 아니다).
     */
    public static boolean isPreflight(String method, String origin, String requestMethodHeader) {
        return "OPTIONS".equalsIgnoreCase(method) && origin != null && requestMethodHeader != null;
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
