package com.edrdog.apiservice.host;

/**
 * 호스트 상태 분류(순수). 열린 alert 의 severity 로만 판정한다.
 * 열린 CRITICAL 이 하나라도 있으면 critical(위험), 없고 HIGH 가 있으면 warning(주의), 둘 다 없으면 healthy(정상).
 */
public final class HostStatus {

    public static final String HEALTHY = "healthy";
    public static final String WARNING = "warning";
    public static final String CRITICAL = "critical";

    private HostStatus() {
    }

    /** 열린 CRITICAL/HIGH 수로 상태를 정한다. CRITICAL 우선. */
    public static String classify(long openCritical, long openHigh) {
        if (openCritical > 0) {
            return CRITICAL;
        }
        if (openHigh > 0) {
            return WARNING;
        }
        return HEALTHY;
    }
}
