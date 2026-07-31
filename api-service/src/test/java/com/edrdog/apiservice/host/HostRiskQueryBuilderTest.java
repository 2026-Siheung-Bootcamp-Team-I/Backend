package com.edrdog.apiservice.host;

import com.edrdog.apiservice.query.ClickHouseQuery;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 위험 점수 재료(host 별 열린 alert severity 분포) SQL 생성 검증.
 * tenant 격리는 강제되어야 하고, 값은 전부 파라미터 바인딩으로만 들어가야 한다.
 */
class HostRiskQueryBuilderTest {

    private final HostRiskQueryBuilder builder = new HostRiskQueryBuilder("edrdog.alerts");
    private static final String TENANT = "1";

    // --- tenant 격리 ---

    @Test
    void tenant_는_항상_바인딩된다() {
        ClickHouseQuery q = builder.hostSeverityCounts(TENANT, null, null, List.of());

        assertTrue(q.sql().contains("tenant_id = {tenant:String}"), q.sql());
        assertEquals(TENANT, q.params().get("tenant"));
    }

    @Test
    void tenant_가_없으면_예외라_쿼리가_만들어지지_않는다() {
        assertThrows(IllegalArgumentException.class,
                () -> builder.hostSeverityCounts(null, null, null, List.of()));
        assertThrows(IllegalArgumentException.class,
                () -> builder.hostSeverityCounts("  ", null, null, List.of()));
    }

    @Test
    void tenant_값은_SQL_본문에_직접_박히지_않는다() {
        ClickHouseQuery q = builder.hostSeverityCounts("1 OR 1=1", null, null, List.of());

        assertFalse(q.sql().contains("1 OR 1=1"), q.sql());
        assertEquals("1 OR 1=1", q.params().get("tenant"));
    }

    // --- 집계 ---

    @Test
    void 호스트별_severity_집계는_alerts_를_host_로_한_번에_묶는다() {
        ClickHouseQuery q = builder.hostSeverityCounts(TENANT, null, null, List.of());

        assertTrue(q.sql().contains("edrdog.alerts FINAL"), q.sql());
        assertTrue(q.sql().contains("countIf(severity = 'CRITICAL') AS critical"), q.sql());
        assertTrue(q.sql().contains("countIf(severity = 'HIGH') AS high"), q.sql());
        assertTrue(q.sql().contains("countIf(severity = 'MEDIUM') AS medium"), q.sql());
        assertTrue(q.sql().contains("countIf(severity = 'LOW') AS low"), q.sql());
        assertTrue(q.sql().contains("GROUP BY host"), q.sql());
    }

    // --- 기간 ---

    @Test
    void 기간을_주면_ts_에_바인딩된다() {
        ClickHouseQuery q = builder.hostSeverityCounts(TENANT, 1000L, 2000L, List.of());

        assertTrue(q.sql().contains("ts >= {from:UInt64}"), q.sql());
        assertTrue(q.sql().contains("ts < {to:UInt64}"), q.sql());
        assertEquals("1000", q.params().get("from"));
        assertEquals("2000", q.params().get("to"));
    }

    @Test
    void 기간이_없으면_ts_조건을_붙이지_않는다() {
        // 엔드포인트 목록은 기간 개념이 없어 전체를 본다.
        ClickHouseQuery q = builder.hostSeverityCounts(TENANT, null, null, List.of());

        assertFalse(q.sql().contains("ts >="), q.sql());
        assertFalse(q.sql().contains("ts <"), q.sql());
    }

    // --- 트리아지 제외 ---

    @Test
    void 트리아지된_알림은_제외_목록으로_빠진다() {
        ClickHouseQuery q = builder.hostSeverityCounts(TENANT, null, null, List.of("a1", "a2"));

        assertTrue(q.sql().contains("id NOT IN ({exc0:String}, {exc1:String})"), q.sql());
        assertEquals("a1", q.params().get("exc0"));
        assertEquals("a2", q.params().get("exc1"));
        assertFalse(q.sql().contains("'a1'"), q.sql());
    }

    @Test
    void 제외_목록이_비면_조건을_붙이지_않는다() {
        assertFalse(builder.hostSeverityCounts(TENANT, null, null, List.of()).sql().contains("NOT IN"));
        assertFalse(builder.hostSeverityCounts(TENANT, null, null, null).sql().contains("NOT IN"));
    }
}
