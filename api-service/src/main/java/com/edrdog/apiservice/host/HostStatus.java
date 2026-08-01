package com.edrdog.apiservice.host;

/**
 * 호스트 상태 분류(순수). 위험 점수(RiskScore)의 함수라 목록에서 두 값이 서로 어긋날 수 없다.
 * 예전에는 열린 CRITICAL/HIGH 의 유무로만 갈라서, MEDIUM 이 54건 쌓여 점수가 100 인 기기가
 * "정상"(초록)으로 뜨는 일이 있었다. 같은 데이터로 두 지표가 정반대를 말하면 어느 쪽도 못 믿는다.
 *
 * <p>임계값을 RiskScore 의 가중치로 두는 이유:
 * 열린 CRITICAL 한 건(25)이면 위험, HIGH 한 건(10)이면 주의라는 기존 의미를 그대로 유지하면서,
 * 가중치가 나중에 바뀌어도 임계값이 같이 따라가 위 모순이 되돌아오지 않게 하려는 것이다.
 * 25/10 을 여기 리터럴로 적으면 한쪽만 고쳐질 수 있다.
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
