package com.edrdog.apiservice.query;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 조회/요약 SQL 생성과 쿼리 제한(limit 클램프)의 순수 로직 검증.
 * tenant 필터는 멀티테넌시 격리를 위해 항상 들어가며, 모든 필터값은 ClickHouse 파라미터
 * 바인딩({x:Type} + params[x])으로만 들어가야 한다(인젝션 차단).
 */
class EventQueryBuilderTest {

    private final EventQueryBuilder builder = new EventQueryBuilder("edrdog.events");
    private static final String TENANT = "1";

    // --- limit 클램프 ---

    @Test
    void limit_이_null_이면_기본값_100() {
        ClickHouseQuery q = builder.events(TENANT, null, null, null, null, null);
        assertTrue(q.sql().contains("LIMIT 100"), q.sql());
    }

    @Test
    void limit_이_0이하이면_기본값_100() {
        assertTrue(builder.events(TENANT, null, null, null, null, 0).sql().contains("LIMIT 100"));
        assertTrue(builder.events(TENANT, null, null, null, null, -5).sql().contains("LIMIT 100"));
    }

    @Test
    void limit_이_상한_1000_을_넘으면_1000으로_클램프() {
        ClickHouseQuery q = builder.events(TENANT, null, null, null, null, 5000);
        assertTrue(q.sql().contains("LIMIT 1000"), q.sql());
    }

    @Test
    void limit_이_범위_안이면_그대로() {
        ClickHouseQuery q = builder.events(TENANT, null, null, null, null, 250);
        assertTrue(q.sql().contains("LIMIT 250"), q.sql());
    }

    // --- tenant 필수 격리 ---

    @Test
    void tenant_는_항상_WHERE_에_바인딩된다() {
        ClickHouseQuery q = builder.events(TENANT, null, null, null, null, 100);
        assertTrue(q.sql().contains("WHERE"), q.sql());
        assertTrue(q.sql().contains("tenant_id = {tenant:String}"), q.sql());
        assertEquals(TENANT, q.params().get("tenant"));
    }

    @Test
    void 다른_필터가_없으면_tenant_만_바인딩된다() {
        ClickHouseQuery q = builder.events(TENANT, null, null, null, null, 100);
        assertEquals(1, q.params().size());
        assertEquals(TENANT, q.params().get("tenant"));
    }

    @Test
    void tenant_값은_SQL_본문에_직접_박히지_않는다() {
        ClickHouseQuery q = builder.events("1 OR 1=1", null, null, null, null, 100);
        assertFalse(q.sql().contains("1 OR 1=1"), q.sql());
        assertEquals("1 OR 1=1", q.params().get("tenant"));
    }

    @Test
    void tenant_가_null_이거나_빈값이면_예외() {
        assertThrows(IllegalArgumentException.class,
                () -> builder.events(null, null, null, null, null, 100));
        assertThrows(IllegalArgumentException.class,
                () -> builder.events("  ", null, null, null, null, 100));
        assertThrows(IllegalArgumentException.class,
                () -> builder.summaryByType(null, null, null));
    }

    // --- WHERE / 파라미터 바인딩 ---

    @Test
    void host_필터는_파라미터_바인딩으로_들어간다() {
        ClickHouseQuery q = builder.events(TENANT, "host-01", null, null, null, 100);
        assertTrue(q.sql().contains("host = {host:String}"), q.sql());
        assertEquals("host-01", q.params().get("host"));
        assertEquals(TENANT, q.params().get("tenant"));
        // 값은 SQL 본문에 직접 박히지 않는다
        assertFalse(q.sql().contains("host-01"), q.sql());
    }

    @Test
    void type_필터_바인딩() {
        ClickHouseQuery q = builder.events(TENANT, null, "process", null, null, 100);
        assertTrue(q.sql().contains("type = {type:String}"), q.sql());
        assertEquals("process", q.params().get("type"));
    }

    @Test
    void 시간범위_from_to_는_ts_에_바인딩() {
        ClickHouseQuery q = builder.events(TENANT, null, null, 1000L, 2000L, 100);
        assertTrue(q.sql().contains("ts >= {from:UInt64}"), q.sql());
        assertTrue(q.sql().contains("ts <= {to:UInt64}"), q.sql());
        assertEquals("1000", q.params().get("from"));
        assertEquals("2000", q.params().get("to"));
    }

    @Test
    void 여러_필터는_AND_로_결합_되고_tenant_도_함께_바인딩() {
        ClickHouseQuery q = builder.events(TENANT, "host-01", "network", null, null, 100);
        assertTrue(q.sql().contains(" AND "), q.sql());
        // tenant + host + type
        assertEquals(3, q.params().size());
        assertEquals(TENANT, q.params().get("tenant"));
    }

    @Test
    void 빈문자열_host_type_은_무시되고_tenant_만_남는다() {
        ClickHouseQuery q = builder.events(TENANT, "  ", "", null, null, 100);
        assertEquals(1, q.params().size());
        assertTrue(q.sql().contains("tenant_id = {tenant:String}"), q.sql());
    }

    @Test
    void 최신순_정렬() {
        assertTrue(builder.events(TENANT, null, null, null, null, 100).sql().contains("ORDER BY ts DESC"));
    }

    // --- 요약 ---

    @Test
    void 요약은_tenant_로_필터하며_type별_집계_쿼리를_만든다() {
        ClickHouseQuery q = builder.summaryByType(TENANT, null, null);
        assertTrue(q.sql().contains("tenant_id = {tenant:String}"), q.sql());
        assertEquals(TENANT, q.params().get("tenant"));
        assertTrue(q.sql().contains("GROUP BY type"), q.sql());
        assertTrue(q.sql().contains("count()"), q.sql());
    }

    @Test
    void 요약도_시간범위_바인딩을_지원() {
        ClickHouseQuery q = builder.summaryByType(TENANT, 1000L, 2000L);
        assertTrue(q.sql().contains("ts >= {from:UInt64}"), q.sql());
        assertEquals("1000", q.params().get("from"));
        assertEquals("2000", q.params().get("to"));
    }
}
