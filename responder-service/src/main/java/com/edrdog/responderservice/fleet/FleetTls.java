package com.edrdog.responderservice.fleet;

/**
 * Fleet 연결 전송 보안 판단(순수 로직).
 *
 * <p>Fleet 호출은 Authorization: Bearer 토큰을 싣는다. 실제 조치(kill)를 켠 상태에서 평문 http 로
 * 나가면 토큰이 그대로 노출되므로, 실행 스위치가 켜진 경우에는 https 를 강제한다.
 * dry-run(스위치 off) 이면 Fleet 을 실제로 부르지 않으므로 로컬 http 기본값을 그대로 둔다.
 */
public final class FleetTls {

    private static final String HTTPS_PREFIX = "https://";

    private FleetTls() {
    }

    /** base-url 이 https 스킴이면 true (대소문자·앞뒤 공백 무시). null/blank 는 false. */
    public static boolean isHttps(String baseUrl) {
        return baseUrl != null && baseUrl.trim().toLowerCase().startsWith(HTTPS_PREFIX);
    }

    /** 실제 조치 실행이 켜졌는데 Fleet 연결이 https 가 아니면 거부한다(평문 토큰 노출 차단). */
    public static void requireHttpsWhenExecuting(String baseUrl, boolean executeEnabled) {
        if (executeEnabled && !isHttps(baseUrl)) {
            throw new IllegalStateException(
                    "실제 조치 실행(RESPONDER_EXECUTE_ENABLED=true)에는 Fleet 연결이 https 여야 합니다. "
                            + "현재 base-url=" + baseUrl);
        }
    }
}
