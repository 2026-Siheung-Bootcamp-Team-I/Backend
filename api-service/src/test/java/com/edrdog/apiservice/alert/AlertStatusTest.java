package com.edrdog.apiservice.alert;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 트리아지 status 검증 순수 로직. PATCH 로 허용되는 값은 confirmed / false_positive 뿐이다.
 * open 은 초기값이라 PATCH 로 되돌릴 수 없다.
 */
class AlertStatusTest {

    @Test
    void 허용된_전이만_통과() {
        assertTrue(AlertStatus.validTransition(AlertStatus.CONFIRMED));
        assertTrue(AlertStatus.validTransition(AlertStatus.FALSE_POSITIVE));
    }

    @Test
    void 초기값_open_과_알수없는_값은_거부() {
        assertFalse(AlertStatus.validTransition(AlertStatus.OPEN));
        assertFalse(AlertStatus.validTransition("deleted"));
        assertFalse(AlertStatus.validTransition(null));
        assertFalse(AlertStatus.validTransition(""));
    }
}
