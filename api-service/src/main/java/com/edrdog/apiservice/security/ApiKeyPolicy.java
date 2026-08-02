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
            "/i/"          // 설치 스크립트 배포. 링크의 설치 토큰 자체가 인증이다(InstallController).
                           // curl 한 줄로 받아야 해서 헤더를 붙일 수가 없다. 대신 토큰을 짧게 살린다.
    );

    /**
     * 정확히 이 경로일 때만 예외인 것들.
     *
     * <p>접두어로 두지 않는 이유는 {@code /api/tenant} 아래에 enroll secret 과 webhook 이 같이
     * 있어서다. 접두어로 열면 그 둘까지 딸려 열린다. 설치 링크는 만료되지만 enroll secret 은
     * 테넌트당 하나에 만료가 없어서, 한 번 새면 되돌릴 방법이 마땅치 않다.
     */
    private static final List<String> EXEMPT_PATHS = List.of(
            // 대시보드(또는 그 대신 쓰는 스크립트)가 부르고 Bearer 로 이미 인증한다. API 키까지
            // 요구하면 기기 하나 추가하려고 사람이 키 두 개를 손에 쥐어야 한다. 설치하는 사람에게서
            // 키를 없애 놓고 만드는 사람에게 남겨 두면 절반만 한 것이다.
            "/api/tenant/install-link"
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

    public boolean isExempt(String path) {
        return EXEMPT_PATHS.contains(path) || EXEMPT_PREFIXES.stream().anyMatch(path::startsWith);
    }

    public boolean isAuthorized(String providedKey) {
        return providedKey != null && !providedKey.isBlank() && configuredKey.equals(providedKey);
    }
}
