package com.edrdog.apiservice.alert;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * 결정적 alert id 순수 로직. 같은 입력은 같은 id, 다른 입력은 다른 id 여야 멱등 적재가 성립한다.
 */
class AlertIdTest {

    @Test
    void 같은_입력은_같은_id() {
        String a = AlertId.of("t1", "host-1", "RULE_A", 1000L);
        String b = AlertId.of("t1", "host-1", "RULE_A", 1000L);
        assertEquals(a, b);
    }

    @Test
    void 필드가_다르면_id도_다르다() {
        String base = AlertId.of("t1", "host-1", "RULE_A", 1000L);
        assertNotEquals(base, AlertId.of("t2", "host-1", "RULE_A", 1000L));
        assertNotEquals(base, AlertId.of("t1", "host-2", "RULE_A", 1000L));
        assertNotEquals(base, AlertId.of("t1", "host-1", "RULE_B", 1000L));
        assertNotEquals(base, AlertId.of("t1", "host-1", "RULE_A", 2000L));
    }
}
