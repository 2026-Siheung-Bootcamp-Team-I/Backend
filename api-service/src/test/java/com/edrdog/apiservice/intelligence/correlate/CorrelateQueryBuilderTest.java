package com.edrdog.apiservice.intelligence.correlate;

import com.edrdog.apiservice.query.ClickHouseQuery;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 상관분석 조회 SQL 생성의 순수 로직 검증.
 * tenant 조건은 남의 조직 데이터가 새지 않도록 항상 강제되어야 하고, 사용자가 준 값은
 * 전부 파라미터 바인딩으로만 들어가야 한다(EventQueryBuilder 와 같은 규칙).
 */
class CorrelateQueryBuilderTest {

    private final CorrelateQueryBuilder builder = new CorrelateQueryBuilder("edrdog.events");
    private static final String TENANT = "7";
    private static final CorrelateTarget DOMAIN = new CorrelateTarget(TargetKind.DOMAIN, "example.com");
    private static final CorrelateTarget IP = new CorrelateTarget(TargetKind.IP, "93.184.216.34");

    // --- tenant 격리 ---

    @Test
    void tenant_가_없으면_조회를_만들지_않는다() {
        assertThrows(IllegalArgumentException.class, () -> builder.seedEvents(null, DOMAIN, null, null, null));
        assertThrows(IllegalArgumentException.class, () -> builder.seedEvents("  ", DOMAIN, null, null, null));
        assertThrows(IllegalArgumentException.class, () -> builder.destinationEvents(null, List.of("1.1.1.1"), 0, 1));
    }

    @Test
    void tenant_는_항상_WHERE_에_바인딩된다() {
        ClickHouseQuery q = builder.seedEvents(TENANT, DOMAIN, null, null, null);
        assertTrue(q.sql().contains("tenant_id = {tenant:String}"), q.sql());
        assertEquals(TENANT, q.params().get("tenant"));

        ClickHouseQuery d = builder.destinationEvents(TENANT, List.of("1.1.1.1"), 0, 1);
        assertTrue(d.sql().contains("tenant_id = {tenant:String}"), d.sql());
        assertEquals(TENANT, d.params().get("tenant"));
    }

    // --- 기준점 조회 ---

    @Test
    void 도메인_기준점은_domain_컬럼으로_찾는다() {
        ClickHouseQuery q = builder.seedEvents(TENANT, DOMAIN, null, null, null);
        assertTrue(q.sql().contains("domain = {seed:String}"), q.sql());
        assertEquals("example.com", q.params().get("seed"));
    }

    @Test
    void IP_기준점은_목적지와_DNS_응답_양쪽에서_찾는다() {
        // 그 IP 로 붙은 이벤트뿐 아니라 그 IP 를 답으로 준 DNS 이벤트도 관계의 한 축이다.
        ClickHouseQuery q = builder.seedEvents(TENANT, IP, null, null, null);
        assertTrue(q.sql().contains("dest_ip = {seed:String}"), q.sql());
        assertTrue(q.sql().contains("JSONExtract(detail, 'answers', 'Array(String)')"), q.sql());
        assertEquals("93.184.216.34", q.params().get("seed"));
    }

    @Test
    void 사용자_값은_SQL_에_직접_박히지_않는다() {
        ClickHouseQuery q = builder.seedEvents(TENANT, new CorrelateTarget(TargetKind.DOMAIN, "evil.com"), null, null, null);
        assertFalse(q.sql().contains("evil.com"), q.sql());
    }

    @Test
    void 시간범위는_주어질_때만_붙는다() {
        assertFalse(builder.seedEvents(TENANT, DOMAIN, null, null, null).sql().contains("{from:UInt64}"));

        ClickHouseQuery q = builder.seedEvents(TENANT, DOMAIN, 100L, 200L, null);
        assertTrue(q.sql().contains("ts >= {from:UInt64}"), q.sql());
        assertTrue(q.sql().contains("ts <= {to:UInt64}"), q.sql());
        assertEquals("100", q.params().get("from"));
        assertEquals("200", q.params().get("to"));
    }

    @Test
    void limit_은_기본값과_상한으로_클램프한다() {
        assertTrue(builder.seedEvents(TENANT, DOMAIN, null, null, null).sql()
                .contains("LIMIT " + CorrelateQueryBuilder.DEFAULT_LIMIT));
        assertTrue(builder.seedEvents(TENANT, DOMAIN, null, null, 0).sql()
                .contains("LIMIT " + CorrelateQueryBuilder.DEFAULT_LIMIT));
        assertTrue(builder.seedEvents(TENANT, DOMAIN, null, null, 999_999).sql()
                .contains("LIMIT " + CorrelateQueryBuilder.MAX_LIMIT));
        assertTrue(builder.seedEvents(TENANT, DOMAIN, null, null, 42).sql().contains("LIMIT 42"));
    }

    @Test
    void 기준점_조회는_상관분석에_쓰는_타입만_본다() {
        String sql = builder.seedEvents(TENANT, DOMAIN, null, null, null).sql();
        assertTrue(sql.contains("type IN ('dns', 'network', 'l7')"), sql);
    }

    // --- 프로세스 보정 후보 조회 ---

    @Test
    void 보정_후보는_접속_이벤트만_그리고_IP_목록으로_찾는다() {
        ClickHouseQuery q = builder.destinationEvents(TENANT, List.of("1.1.1.1", "8.8.8.8"), 100L, 200L);

        assertTrue(q.sql().contains("type IN ('network', 'l7')"), q.sql());
        assertTrue(q.sql().contains("dest_ip IN ({ip0:String}, {ip1:String})"), q.sql());
        assertEquals("1.1.1.1", q.params().get("ip0"));
        assertEquals("8.8.8.8", q.params().get("ip1"));
        assertEquals("100", q.params().get("from"));
        assertEquals("200", q.params().get("to"));
    }

    @Test
    void 보정할_IP_가_없으면_조회를_만들지_않는다() {
        assertThrows(IllegalArgumentException.class, () -> builder.destinationEvents(TENANT, List.of(), 0, 1));
    }

    @Test
    void 보정_후보_IP_개수는_상한으로_자른다() {
        // 응답 IP 가 많은 도메인 하나로 IN 절이 끝없이 길어지지 않게 막는다.
        List<String> many = java.util.stream.IntStream.range(0, CorrelateQueryBuilder.MAX_DEST_IPS + 50)
                .mapToObj(i -> "10.0.0." + i)
                .toList();

        ClickHouseQuery q = builder.destinationEvents(TENANT, many, 0, 1);

        assertTrue(q.params().containsKey("ip" + (CorrelateQueryBuilder.MAX_DEST_IPS - 1)), q.sql());
        assertFalse(q.params().containsKey("ip" + CorrelateQueryBuilder.MAX_DEST_IPS), q.sql());
    }
}
