package com.edrdog.apiservice.host;

/**
 * 엔드포인트 위험 점수(0..100, 순수). 새로 수집하는 값 없이 이미 관측된 열린 alert 만 severity 로 가중합한다.
 *
 * <p>intelligence/topology 가 아니라 host 에 두는 이유:
 * 점수는 호스트에 대한 값이지 토폴로지 화면 전용 개념이 아니고, 목록(GET /api/hosts)과 토폴로지가 같이 쓴다.
 * topology 에 두면 도메인(host)이 화면 기능(intelligence)에 의존하게 되므로 방향을 뒤집었다.
 *
 * <p>가중치를 25/10/3/1 로 둔 이유:
 * CRITICAL 한 건이면 25점이라 그 호스트 하나만으로 화면 상단에 올라와야 하고, 네 건이면 상한 100 에 닿는다.
 * HIGH 두 건(20)보다 CRITICAL 한 건(25)이 무거워야 HostStatus 의 분류(CRITICAL 하나면 위험,
 * HIGH 하나면 주의)와 순서가 어긋나지 않는다. MEDIUM/LOW 는 쌓였을 때만 의미가 있어 낮게 둔다
 * (낮게 두는 것과 무시하는 것은 다르다. 쌓여서 임계를 넘으면 HostStatus 도 같이 올라간다).
 * 상한을 두는 이유는 알림이 폭주한 호스트 하나가 점수 축을 독차지하면 나머지가 전부 0 으로 보이기 때문이다.
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
