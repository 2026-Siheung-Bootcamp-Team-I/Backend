package com.edrdog.apiservice.host;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 엔드포인트 위험 점수(관측된 열린 alert 의 severity 가중합) 검증. */
class RiskScoreTest {

    @Test
    void 알림이_없으면_0점() {
        assertEquals(0, RiskScore.of(0, 0, 0, 0));
    }

    @Test
    void severity_가_높을수록_가중치가_크다() {
        assertTrue(RiskScore.of(1, 0, 0, 0) > RiskScore.of(0, 1, 0, 0));
        assertTrue(RiskScore.of(0, 1, 0, 0) > RiskScore.of(0, 0, 1, 0));
        assertTrue(RiskScore.of(0, 0, 1, 0) > RiskScore.of(0, 0, 0, 1));
    }

    @Test
    void 같은_severity_는_건수만큼_누적된다() {
        assertEquals(RiskScore.of(1, 0, 0, 0) * 2, RiskScore.of(2, 0, 0, 0));
    }

    @Test
    void 상한은_100_이라_점수가_넘치지_않는다() {
        assertEquals(100, RiskScore.of(1000, 1000, 1000, 1000));
        assertEquals(100, RiskScore.of(4, 0, 0, 0));
    }

    @Test
    void CRITICAL_한_건은_HIGH_두_건보다_무겁다() {
        // HostStatus 가 CRITICAL 하나로 '위험', HIGH 하나로 '주의' 로 가르는 순서를 점수에서도 지킨다.
        assertTrue(RiskScore.of(1, 0, 0, 0) > RiskScore.of(0, 2, 0, 0));
    }
}
