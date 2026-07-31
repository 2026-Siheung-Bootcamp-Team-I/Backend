package com.edrdog.apiservice.intelligence.topology;

/**
 * 엔드포인트 위험 점수(0..100, 순수). 새로 수집하는 값 없이 이미 관측된 열린 alert 만 severity 로 가중합한다.
 *
 * <p>가중치를 25/10/3/1 로 둔 이유:
 * CRITICAL 한 건이면 25점이라 그 호스트 하나만으로 화면 상단에 올라와야 하고, 네 건이면 상한 100 에 닿는다.
 * HIGH 두 건(20)보다 CRITICAL 한 건(25)이 무거워야 HostStatus 의 분류(CRITICAL 하나면 위험,
 * HIGH 하나면 주의)와 순서가 어긋나지 않는다. MEDIUM/LOW 는 쌓였을 때만 의미가 있어 낮게 둔다.
 * 상한을 두는 이유는 알림이 폭주한 호스트 하나가 점수 축을 독차지하면 나머지가 전부 0 으로 보이기 때문이다.
 */
public final class RiskScore {

    private static final int W_CRITICAL = 25;
    private static final int W_HIGH = 10;
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
