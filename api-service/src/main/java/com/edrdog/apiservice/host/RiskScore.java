package com.edrdog.apiservice.host;

/**
 * 엔드포인트 위험 점수(0..100, 순수). 새로 수집하는 값 없이 이미 관측된 열린 alert 만 severity 로 가중합한다.
 * 상한을 빼면 알림이 폭주한 호스트 하나가 점수 축을 독차지해 나머지가 전부 0 으로 보인다.
 */
public final class RiskScore {

    /** HostStatus 의 위험/주의 임계값이 이 둘을 그대로 쓴다. 임계값이 가중치를 따라가야 상태와 점수가 갈리지 않는다. */
    public static final int W_CRITICAL = 25;
    public static final int W_HIGH = 10;

    private static final int W_MEDIUM = 3;
    private static final int W_LOW = 1;
    private static final int MAX = 100;

    private RiskScore() {
    }

    public static int of(long critical, long high, long medium, long low) {
        long weighted = critical * W_CRITICAL + high * W_HIGH + medium * W_MEDIUM + low * W_LOW;
        return (int) Math.min(MAX, weighted);
    }
}
