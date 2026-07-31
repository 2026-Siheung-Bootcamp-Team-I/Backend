package com.edrdog.apiservice.alert;

import com.edrdog.apiservice.query.ClickHouseQuery;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * alerts SQL 생성 순수 검증(ClickHouse 없이). tenant 격리 강제, FINAL dedup, 필터·IN/NOT IN·집계 SQL 모양을 본다.
 * 실제 실행(집계 결과)은 ClickHouse 가 있어야 하므로 여기서는 SQL/파라미터만 검증한다.
 */
class AlertQueryBuilderTest {

    private final AlertQueryBuilder b = new AlertQueryBuilder("edrdog.alerts");

    @Test
    void tenant_없으면_예외() {
        assertThrows(IllegalArgumentException.class,
                () -> b.search(null, null, null, null, null, null, null, null));
    }

    @Test
    void search_는_FINAL과_tenant격리_최신순_클램프() {
        ClickHouseQuery q = b.search("A", null, null, null, null, null, null, null);
        assertTrue(q.sql().contains("FROM edrdog.alerts FINAL"), q.sql());
        assertTrue(q.sql().contains("tenant_id = {tenant:String}"), q.sql());
        assertTrue(q.sql().contains("ORDER BY ts DESC LIMIT 100"), q.sql());
        assertEquals("A", q.params().get("tenant"));
    }

    @Test
    void search_는_host_severity_시간범위_필터를_바인딩한다() {
        ClickHouseQuery q = b.search("A", "h1", "HIGH", 100L, 300L, 10, null, null);
        assertTrue(q.sql().contains("host = {host:String}"), q.sql());
        assertTrue(q.sql().contains("severity = {severity:String}"), q.sql());
        assertTrue(q.sql().contains("ts >= {from:UInt64}"), q.sql());
        assertTrue(q.sql().contains("ts < {to:UInt64}"), q.sql());
        assertTrue(q.sql().contains("LIMIT 10"), q.sql());
        assertEquals("h1", q.params().get("host"));
        assertEquals("HIGH", q.params().get("severity"));
        assertEquals("100", q.params().get("from"));
        assertEquals("300", q.params().get("to"));
    }

    // --- domain/destIp: 관계 분석 화면에서 도메인/목적지를 짚어 "이것 때문에 난 알림"으로 넘어가는 필터 ---

    @Test
    void search_는_domain_미지정시_조건을_넣지_않는다() {
        ClickHouseQuery q = b.search("A", null, null, null, null, null, null, null, null, null);
        assertTrue(!q.sql().contains("domain ="), q.sql());
        assertTrue(!q.sql().contains("dest_ip ="), q.sql());
    }

    @Test
    void search_는_domain으로_거른다_대소문자_무관() {
        // 도메인은 소문자로 정규화되어 적재되므로(agent 의 normalizeDNSName) 대문자로 검색해도 같은 도메인을 찾아야 한다.
        ClickHouseQuery q = b.search("A", null, null, "EVIL.EXAMPLE.COM", null, null, null, null, null, null);
        assertTrue(q.sql().contains("domain = {domain:String}"), q.sql());
        assertEquals("evil.example.com", q.params().get("domain"));
    }

    @Test
    void search_는_destIp로_거른다() {
        ClickHouseQuery q = b.search("A", null, null, null, "203.0.113.9", null, null, null, null, null);
        assertTrue(q.sql().contains("dest_ip = {destIp:String}"), q.sql());
        assertEquals("203.0.113.9", q.params().get("destIp"));
    }

    @Test
    void search_는_domain과_destIp를_함께_주면_둘다_적용한다() {
        ClickHouseQuery q = b.search("A", null, null, "evil.example.com", "203.0.113.9",
                null, null, null, null, null);
        assertTrue(q.sql().contains("domain = {domain:String}"), q.sql());
        assertTrue(q.sql().contains("dest_ip = {destIp:String}"), q.sql());
        assertEquals("evil.example.com", q.params().get("domain"));
        assertEquals("203.0.113.9", q.params().get("destIp"));
    }

    @Test
    void search_는_domain_빈문자열도_미지정과_다르게_걸러_관측안된_목적지를_찾는다() {
        // edrdog.alerts 에서 목적지를 관측 못한 알림은 domain/dest_ip 가 빈 문자열로 적재된다.
        // 빈 문자열로 걸러도 미지정(null)과 같은 뜻이 되면 그 알림들을 못 찾는다.
        ClickHouseQuery q = b.search("A", null, null, "", null, null, null, null, null, null);
        assertTrue(q.sql().contains("domain = {domain:String}"), q.sql());
        assertEquals("", q.params().get("domain"));
    }

    @Test
    void search_는_destIp_빈문자열도_미지정과_다르게_거른다() {
        ClickHouseQuery q = b.search("A", null, null, null, "", null, null, null, null, null);
        assertTrue(q.sql().contains("dest_ip = {destIp:String}"), q.sql());
        assertEquals("", q.params().get("destIp"));
    }

    @Test
    void search_는_destIp로_거른다_IPv6_대소문자_무관() {
        // IPv6 는 16진수라 대소문자가 같은 주소다. Go net.IP.String() 은 항상 소문자로 적재하므로 검색어도 맞춘다.
        ClickHouseQuery q = b.search("A", null, null, null, "2001:DB8::1", null, null, null, null, null);
        assertTrue(q.sql().contains("dest_ip = {destIp:String}"), q.sql());
        assertEquals("2001:db8::1", q.params().get("destIp"));
    }

    @Test
    void search_는_domain_필터를_줘도_tenant격리는_유지한다() {
        ClickHouseQuery q = b.search("A", null, null, "evil.example.com", null, null, null, null, null, null);
        assertTrue(q.sql().contains("tenant_id = {tenant:String}"), q.sql());
        assertEquals("A", q.params().get("tenant"));
    }

    @Test
    void search_는_limit_상한으로_클램프() {
        assertTrue(b.search("A", null, null, null, null, 99999, null, null).sql().contains("LIMIT 1000"));
    }

    @Test
    void search_includeIds_는_IN_으로_좁힌다() {
        ClickHouseQuery q = b.search("A", null, null, null, null, null, List.of("x", "y"), null);
        assertTrue(q.sql().contains("id IN ({inc0:String}, {inc1:String})"), q.sql());
        assertEquals("x", q.params().get("inc0"));
        assertEquals("y", q.params().get("inc1"));
    }

    @Test
    void search_excludeIds_는_NOT_IN_으로_뺀다() {
        ClickHouseQuery q = b.search("A", null, null, null, null, null, null, List.of("x"));
        assertTrue(q.sql().contains("id NOT IN ({exc0:String})"), q.sql());
        assertEquals("x", q.params().get("exc0"));
    }

    @Test
    void search_빈_id목록은_조건을_넣지_않는다() {
        ClickHouseQuery q = b.search("A", null, null, null, null, null, List.of(), List.of());
        assertTrue(!q.sql().contains(" IN ("), q.sql());
    }

    @Test
    void byId_는_id바인딩과_LIMIT1() {
        ClickHouseQuery q = b.byId("A", "the-id");
        assertTrue(q.sql().contains("FROM edrdog.alerts FINAL"), q.sql());
        assertTrue(q.sql().contains("id = {id:String}"), q.sql());
        assertTrue(q.sql().contains("LIMIT 1"), q.sql());
        assertEquals("the-id", q.params().get("id"));
        assertEquals("A", q.params().get("tenant"));
    }

    @Test
    void countBySeverity_는_severity로_GROUP() {
        ClickHouseQuery q = b.countBySeverity("A", 100L, 300L);
        assertTrue(q.sql().contains("SELECT severity, count() AS cnt"), q.sql());
        assertTrue(q.sql().contains("GROUP BY severity"), q.sql());
        assertTrue(q.sql().contains("ts >= {from:UInt64}"), q.sql());
        assertTrue(q.sql().contains("ts < {to:UInt64}"), q.sql());
    }

    @Test
    void countByRuleId_는_ruleId로_GROUP() {
        ClickHouseQuery q = b.countByRuleId("A", null, null);
        assertTrue(q.sql().contains("SELECT rule_id, count() AS cnt"), q.sql());
        assertTrue(q.sql().contains("GROUP BY rule_id"), q.sql());
    }

    @Test
    void timeseries_는_버킷정렬과_severity로_GROUP() {
        ClickHouseQuery q = b.timeseries("A", 0L, 7200000L, 3600000L);
        assertTrue(q.sql().contains("intDiv(ts, 3600000) * 3600000 AS bucketStart"), q.sql());
        assertTrue(q.sql().contains("GROUP BY bucketStart, severity"), q.sql());
        assertEquals("0", q.params().get("from"));
        assertEquals("7200000", q.params().get("to"));
    }

    @Test
    void openHostCounts_는_host별_열린수와_severity_countIf() {
        ClickHouseQuery q = b.openHostCounts("A", List.of("triaged1"));
        assertTrue(q.sql().contains("count() AS openTotal"), q.sql());
        assertTrue(q.sql().contains("countIf(severity = 'CRITICAL') AS openCritical"), q.sql());
        assertTrue(q.sql().contains("countIf(severity = 'HIGH') AS openHigh"), q.sql());
        assertTrue(q.sql().contains("GROUP BY host"), q.sql());
        assertTrue(q.sql().contains("id NOT IN ({exc0:String})"), q.sql());
        assertEquals("triaged1", q.params().get("exc0"));
    }

    @Test
    void openHostCounts_트리아지_없으면_제외조건_없음() {
        assertTrue(!b.openHostCounts("A", List.of()).sql().contains("NOT IN"));
    }
}
