package com.edrdog.archiverservice.alert;

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

    /** 모듈을 넘는 고정값. api-service AlertIdTest 에 같은 값이 박혀 있어 두 사본이 어긋나면 한쪽이 깨진다. */
    // 이 테스트가 없으면 위의 두 테스트는 씨앗 형식을 바꿔도 그대로 통과한다(자기 모듈 안에서만 일관되면 되므로).
    @Test
    void 씨앗_형식이_바뀌면_실패한다() {
        assertEquals("b5e40e20-dce7-3e32-bb6a-8f944d0559f7", AlertId.of("t1", "host-1", "RULE_A", 1000L));
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
