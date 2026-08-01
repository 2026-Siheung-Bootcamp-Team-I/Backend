package com.edrdog.apiservice.host;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 호스트 상태 분류 순수 로직. status 는 위험 점수의 함수다.
 */
class HostStatusTest {

    @Test
    void 열린_CRITICAL_한_건이면_위험() {
        assertEquals(HostStatus.CRITICAL, HostStatus.classify(RiskScore.of(1, 0, 0, 0)));
    }

    @Test
    void CRITICAL_없고_HIGH_한_건이면_주의() {
        assertEquals(HostStatus.WARNING, HostStatus.classify(RiskScore.of(0, 1, 0, 0)));
    }

    @Test
    void 열린것이_없으면_정상() {
        assertEquals(HostStatus.HEALTHY, HostStatus.classify(RiskScore.of(0, 0, 0, 0)));
    }

    @Test
    void MEDIUM_만_쌓여도_점수를_따라_주의와_위험으로_올라간다() {
        assertEquals(HostStatus.HEALTHY, HostStatus.classify(RiskScore.of(0, 0, 3, 0)));
        assertEquals(HostStatus.WARNING, HostStatus.classify(RiskScore.of(0, 0, 4, 0)));
        assertEquals(HostStatus.CRITICAL, HostStatus.classify(RiskScore.of(0, 0, 54, 0)));
    }

    @Test
    void 임계값은_RiskScore_의_가중치에_묶여있다() {
        assertEquals(HostStatus.CRITICAL, HostStatus.classify(RiskScore.W_CRITICAL));
        assertEquals(HostStatus.WARNING, HostStatus.classify(RiskScore.W_CRITICAL - 1));
        assertEquals(HostStatus.WARNING, HostStatus.classify(RiskScore.W_HIGH));
        assertEquals(HostStatus.HEALTHY, HostStatus.classify(RiskScore.W_HIGH - 1));
    }
}
