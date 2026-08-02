package com.edrdog.apiservice.query;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 조회 입력 가드(공백 판정, limit 클램프, offset 절) 검증. 빌더마다 다시 구현하던 규칙을 한곳에 모은 것이다. */
class QueryGuardsTest {

    @Test
    void 공백만_있는_문자열은_값이_없는_것으로_본다() {
        assertFalse(QueryGuards.hasText(null));
        assertFalse(QueryGuards.hasText("  "));
        assertTrue(QueryGuards.hasText(" x "));
    }

    @Test
    void limit_은_없거나_0이하면_기본값_상한을_넘으면_상한() {
        assertEquals(100, QueryGuards.clampLimit(null, 100, 1000));
        assertEquals(100, QueryGuards.clampLimit(0, 100, 1000));
        assertEquals(100, QueryGuards.clampLimit(-5, 100, 1000));
        assertEquals(250, QueryGuards.clampLimit(250, 100, 1000));
        assertEquals(1000, QueryGuards.clampLimit(5000, 100, 1000));
    }

    @Test
    void offset_이_없거나_0이면_절을_붙이지_않는다() {
        assertEquals("", QueryGuards.offsetClause(null, 10_000));
        assertEquals("", QueryGuards.offsetClause(0, 10_000));
    }

    @Test
    void offset_은_범위_안이면_그대로_붙는다() {
        assertEquals(" OFFSET 100", QueryGuards.offsetClause(100, 10_000));
        assertEquals(" OFFSET 10000", QueryGuards.offsetClause(10_000, 10_000));
    }

    @Test
    void 범위_밖_offset_은_클램프하지_않고_거절한다() {
        // 조용히 잘라내면 화면이 빈 페이지를 데이터 없음으로 읽는다.
        assertThrows(IllegalArgumentException.class, () -> QueryGuards.offsetClause(10_001, 10_000));
        assertThrows(IllegalArgumentException.class, () -> QueryGuards.offsetClause(-1, 10_000));
    }
}
