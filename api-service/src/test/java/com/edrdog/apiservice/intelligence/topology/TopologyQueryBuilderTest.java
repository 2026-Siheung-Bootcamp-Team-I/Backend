package com.edrdog.apiservice.intelligence.topology;

import com.edrdog.apiservice.query.ClickHouseQuery;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * egress 토폴로지 SQL 생성 검증. tenant 격리는 모든 쿼리에서 강제되어야 하고,
 * 필터값은 전부 파라미터 바인딩({x:Type})으로만 들어가야 한다(EventQueryBuilderTest 와 같은 계약).
 */
class TopologyQueryBuilderTest {

    private final TopologyQueryBuilder builder = new TopologyQueryBuilder("edrdog.events", "edrdog.alerts");
    private static final String TENANT = "1";

    // --- tenant 격리 ---

    @Test
    void 모든_쿼리에_tenant_가_바인딩된다() {
        List<ClickHouseQuery> queries = List.of(
                builder.egressRelations(TENANT, 1000L, 2000L, null, null),
                builder.relationTotal(TENANT, 1000L, 2000L, null),
                builder.relationAlertCounts(TENANT, 1000L, 2000L));
        for (ClickHouseQuery q : queries) {
            assertTrue(q.sql().contains("tenant_id = {tenant:String}"), q.sql());
            assertEquals(TENANT, q.params().get("tenant"));
        }
    }

    @Test
    void tenant_가_없으면_예외라_쿼리가_만들어지지_않는다() {
        assertThrows(IllegalArgumentException.class,
                () -> builder.egressRelations(null, 1000L, 2000L, null, null));
        assertThrows(IllegalArgumentException.class,
                () -> builder.egressRelations("  ", 1000L, 2000L, null, null));
        assertThrows(IllegalArgumentException.class, () -> builder.relationTotal(null, 1000L, 2000L, null));
        assertThrows(IllegalArgumentException.class, () -> builder.relationAlertCounts(null, 1000L, 2000L));
    }

    @Test
    void tenant_값은_SQL_본문에_직접_박히지_않는다() {
        ClickHouseQuery q = builder.egressRelations("1 OR 1=1", 1000L, 2000L, null, null);
        assertFalse(q.sql().contains("1 OR 1=1"), q.sql());
        assertEquals("1 OR 1=1", q.params().get("tenant"));
    }

    // --- 기간 ---

    @Test
    void 기간은_ts_에_바인딩된다() {
        ClickHouseQuery q = builder.egressRelations(TENANT, 1000L, 2000L, null, null);
        assertTrue(q.sql().contains("ts >= {from:UInt64}"), q.sql());
        assertTrue(q.sql().contains("ts < {to:UInt64}"), q.sql());
        assertEquals("1000", q.params().get("from"));
        assertEquals("2000", q.params().get("to"));
    }

    // --- 관계 집계 ---

    @Test
    void 목적지는_도메인이_있으면_도메인_없으면_IP_다() {
        // dns 이벤트는 dest_ip 가 비어 있고, network 이벤트는 domain 이 비어 있다.
        String sql = builder.egressRelations(TENANT, 1000L, 2000L, null, null).sql();
        assertTrue(sql.contains("if(domain != '', domain, dest_ip) AS dest"), sql);
        assertTrue(sql.contains("if(domain != '', 'domain', 'ip') AS destKind"), sql);
    }

    @Test
    void 목적지가_없는_이벤트는_제외한다() {
        String sql = builder.egressRelations(TENANT, 1000L, 2000L, null, null).sql();
        assertTrue(sql.contains("(domain != '' OR dest_ip != '')"), sql);
    }

    @Test
    void 관계는_host_와_목적지로_묶고_이벤트수_최신시각_프로토콜을_집계한다() {
        String sql = builder.egressRelations(TENANT, 1000L, 2000L, null, null).sql();
        assertTrue(sql.contains("GROUP BY host, dest, destKind"), sql);
        assertTrue(sql.contains("count() AS events"), sql);
        assertTrue(sql.contains("max(ts) AS lastSeen"), sql);
        assertTrue(sql.contains("JSONExtractString(detail, 'protocol')"), sql);
        assertTrue(sql.contains("JSONExtractString(detail, 'l7Protocol')"), sql);
    }

    @Test
    void 관계는_이벤트_많은_순() {
        assertTrue(builder.egressRelations(TENANT, 1000L, 2000L, null, null).sql()
                .contains("ORDER BY events DESC"));
    }

    // --- Top-N 클램프 ---

    @Test
    void limit_이_null_이거나_0이하면_기본값() {
        assertTrue(builder.egressRelations(TENANT, 1000L, 2000L, null, null).sql()
                .contains("LIMIT " + TopologyQueryBuilder.DEFAULT_LIMIT));
        assertTrue(builder.egressRelations(TENANT, 1000L, 2000L, null, 0).sql()
                .contains("LIMIT " + TopologyQueryBuilder.DEFAULT_LIMIT));
        assertTrue(builder.egressRelations(TENANT, 1000L, 2000L, null, -3).sql()
                .contains("LIMIT " + TopologyQueryBuilder.DEFAULT_LIMIT));
    }

    @Test
    void limit_은_상한으로_클램프된다() {
        assertTrue(builder.egressRelations(TENANT, 1000L, 2000L, null, 100000).sql()
                .contains("LIMIT " + TopologyQueryBuilder.MAX_LIMIT));
    }

    @Test
    void limit_이_범위_안이면_그대로() {
        assertTrue(builder.egressRelations(TENANT, 1000L, 2000L, null, 50).sql().contains("LIMIT 50"));
    }

    // --- 검색어 ---

    @Test
    void 검색어는_host_domain_dest_ip_에_부분일치로_바인딩된다() {
        ClickHouseQuery q = builder.egressRelations(TENANT, 1000L, 2000L, "example", null);
        assertTrue(q.sql().contains("host ILIKE {q:String}"), q.sql());
        assertTrue(q.sql().contains("domain ILIKE {q:String}"), q.sql());
        assertTrue(q.sql().contains("dest_ip ILIKE {q:String}"), q.sql());
        assertEquals("%example%", q.params().get("q"));
        assertFalse(q.sql().contains("example"), q.sql());
    }

    @Test
    void 빈_검색어는_필터로_치지_않는다() {
        ClickHouseQuery q = builder.egressRelations(TENANT, 1000L, 2000L, "   ", null);
        assertFalse(q.sql().contains("ILIKE"), q.sql());
        assertEquals(3, q.params().size());   // tenant + from + to
    }

    @Test
    void 검색어의_와일드카드는_이스케이프해_문자로_찾는다() {
        // 이스케이프하지 않으면 사용자가 넣은 % 하나로 전체가 매치돼 검색이 아니게 된다.
        assertEquals("%a\\%b%", builder.egressRelations(TENANT, 1000L, 2000L, "a%b", null).params().get("q"));
        assertEquals("%a\\_b%", builder.egressRelations(TENANT, 1000L, 2000L, "a_b", null).params().get("q"));
        assertEquals("%a\\\\b%", builder.egressRelations(TENANT, 1000L, 2000L, "a\\b", null).params().get("q"));
    }

    @Test
    void 전체_관계수도_같은_검색어로_센다() {
        // Top-N 으로 자른 뒤 "전체 몇 건 중 몇 건" 을 말하려면 자르기 전 수를 같은 조건으로 세야 한다.
        ClickHouseQuery q = builder.relationTotal(TENANT, 1000L, 2000L, "example");
        assertTrue(q.sql().contains("uniqExact((host, if(domain != '', domain, dest_ip)))"), q.sql());
        assertEquals("%example%", q.params().get("q"));
        assertFalse(q.sql().contains("LIMIT"), q.sql());
    }

    // --- 관계별 알림 수 ---

    @Test
    void 관계별_알림수는_alerts_를_FINAL_로_읽고_같은_목적지_규칙으로_묶는다() {
        ClickHouseQuery q = builder.relationAlertCounts(TENANT, 1000L, 2000L);
        assertTrue(q.sql().contains("edrdog.alerts FINAL"), q.sql());
        assertTrue(q.sql().contains("if(domain != '', domain, dest_ip) AS dest"), q.sql());
        assertTrue(q.sql().contains("GROUP BY host, dest"), q.sql());
        assertTrue(q.sql().contains("(domain != '' OR dest_ip != '')"), q.sql());
    }
}
