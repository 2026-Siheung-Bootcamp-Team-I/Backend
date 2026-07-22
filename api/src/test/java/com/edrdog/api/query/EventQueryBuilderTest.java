package com.edrdog.api.query;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 조회/요약 SQL 생성과 쿼리 제한(limit 클램프)의 순수 로직 검증.
 * 필터값은 ClickHouse 파라미터 바인딩({x:Type} + params[x])으로만 들어가야 한다(인젝션 차단).
 */
class EventQueryBuilderTest {

    private final EventQueryBuilder builder = new EventQueryBuilder("edrdog.events");

    // --- limit 클램프 ---

    @Test
    void limit_이_null_이면_기본값_100() {
        ClickHouseQuery q = builder.events(null, null, null, null, null);
        assertTrue(q.sql().contains("LIMIT 100"), q.sql());
    }

    @Test
    void limit_이_0이하이면_기본값_100() {
        assertTrue(builder.events(null, null, null, null, 0).sql().contains("LIMIT 100"));
        assertTrue(builder.events(null, null, null, null, -5).sql().contains("LIMIT 100"));
    }

    @Test
    void limit_이_상한_1000_을_넘으면_1000으로_클램프() {
        ClickHouseQuery q = builder.events(null, null, null, null, 5000);
        assertTrue(q.sql().contains("LIMIT 1000"), q.sql());
    }

    @Test
    void limit_이_범위_안이면_그대로() {
        ClickHouseQuery q = builder.events(null, null, null, null, 250);
        assertTrue(q.sql().contains("LIMIT 250"), q.sql());
    }

    // --- WHERE / 파라미터 바인딩 ---

    @Test
    void 필터가_없으면_WHERE_없고_파라미터_비어있음() {
        ClickHouseQuery q = builder.events(null, null, null, null, 100);
        assertFalse(q.sql().contains("WHERE"), q.sql());
        assertTrue(q.params().isEmpty());
    }

    @Test
    void host_필터는_파라미터_바인딩으로_들어간다() {
        ClickHouseQuery q = builder.events("host-01", null, null, null, 100);
        assertTrue(q.sql().contains("host = {host:String}"), q.sql());
        assertEquals("host-01", q.params().get("host"));
        // 값은 SQL 본문에 직접 박히지 않는다
        assertFalse(q.sql().contains("host-01"), q.sql());
    }

    @Test
    void type_필터_바인딩() {
        ClickHouseQuery q = builder.events(null, "process", null, null, 100);
        assertTrue(q.sql().contains("type = {type:String}"), q.sql());
        assertEquals("process", q.params().get("type"));
    }

    @Test
    void 시간범위_from_to_는_ts_에_바인딩() {
        ClickHouseQuery q = builder.events(null, null, 1000L, 2000L, 100);
        assertTrue(q.sql().contains("ts >= {from:UInt64}"), q.sql());
        assertTrue(q.sql().contains("ts <= {to:UInt64}"), q.sql());
        assertEquals("1000", q.params().get("from"));
        assertEquals("2000", q.params().get("to"));
    }

    @Test
    void 여러_필터는_AND_로_결합() {
        ClickHouseQuery q = builder.events("host-01", "network", null, null, 100);
        assertTrue(q.sql().contains("WHERE"), q.sql());
        assertTrue(q.sql().contains(" AND "), q.sql());
        assertEquals(2, q.params().size());
    }

    @Test
    void 빈문자열_필터는_무시() {
        ClickHouseQuery q = builder.events("  ", "", null, null, 100);
        assertFalse(q.sql().contains("WHERE"), q.sql());
        assertTrue(q.params().isEmpty());
    }

    @Test
    void 최신순_정렬() {
        assertTrue(builder.events(null, null, null, null, 100).sql().contains("ORDER BY ts DESC"));
    }

    // --- 요약 ---

    @Test
    void 요약은_type별_집계_쿼리를_만든다() {
        ClickHouseQuery q = builder.summaryByType(null, null);
        assertTrue(q.sql().contains("GROUP BY type"), q.sql());
        assertTrue(q.sql().contains("count()"), q.sql());
    }

    @Test
    void 요약도_시간범위_바인딩을_지원() {
        ClickHouseQuery q = builder.summaryByType(1000L, 2000L);
        assertTrue(q.sql().contains("ts >= {from:UInt64}"), q.sql());
        assertEquals("1000", q.params().get("from"));
        assertEquals("2000", q.params().get("to"));
    }
}
