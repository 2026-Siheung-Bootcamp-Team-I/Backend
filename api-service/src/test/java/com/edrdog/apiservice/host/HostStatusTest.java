package com.edrdog.apiservice.host;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 호스트 상태 분류 순수 로직. 열린 CRITICAL 우선, 없으면 HIGH, 둘 다 없으면 정상.
 */
class HostStatusTest {

    @Test
    void 열린_CRITICAL_이_있으면_위험() {
        assertEquals(HostStatus.CRITICAL, HostStatus.classify(1, 0));
        assertEquals(HostStatus.CRITICAL, HostStatus.classify(2, 3));
    }

    @Test
    void CRITICAL_없고_HIGH_있으면_주의() {
        assertEquals(HostStatus.WARNING, HostStatus.classify(0, 1));
        assertEquals(HostStatus.WARNING, HostStatus.classify(0, 5));
    }

    @Test
    void 열린것이_없으면_정상() {
        assertEquals(HostStatus.HEALTHY, HostStatus.classify(0, 0));
    }

    @Test
    void CRITICAL_이_HIGH_보다_우선() {
        assertEquals(HostStatus.CRITICAL, HostStatus.classify(1, 10));
    }
}
