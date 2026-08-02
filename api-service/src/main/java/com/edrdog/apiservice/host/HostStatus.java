package com.edrdog.apiservice.host;

/**
 * 호스트 상태 분류(순수). 위험 점수(RiskScore)의 함수라 목록에서 두 값이 서로 어긋날 수 없다.
 * 임계값을 25/10 리터럴로 적으면 RiskScore 가중치와 따로 놀아 "위험도 100 인데 정상"이 되돌아온다.
 */
public final class HostStatus {

    public static final String HEALTHY = "healthy";
    public static final String WARNING = "warning";
    public static final String CRITICAL = "critical";

    private static final int CRITICAL_AT = RiskScore.W_CRITICAL;
    private static final int WARNING_AT = RiskScore.W_HIGH;

    private HostStatus() {
    }

    public static String classify(int riskScore) {
        if (riskScore >= CRITICAL_AT) {
            return CRITICAL;
        }
        if (riskScore >= WARNING_AT) {
            return WARNING;
        }
        return HEALTHY;
    }
}
