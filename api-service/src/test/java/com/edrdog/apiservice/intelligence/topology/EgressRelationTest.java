package com.edrdog.apiservice.intelligence.topology;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** ClickHouse 집계 행 -> 값 객체 변환 검증(UInt64 는 JSON 에서 문자열로 오고, 프로토콜은 두 칸에 나뉘어 온다). */
class EgressRelationTest {

    private static Map<String, Object> row(Object events, Object lastSeen, List<String> protocols,
                                           List<String> l7Protocols) {
        Map<String, Object> row = new HashMap<>();
        row.put("host", "h1");
        row.put("dest", "api.example.com");
        row.put("destKind", "domain");
        row.put("events", events);
        row.put("lastSeen", lastSeen);
        row.put("protocols", protocols);
        row.put("l7Protocols", l7Protocols);
        return row;
    }

    @Test
    void 문자열로_온_UInt64_를_숫자로_읽는다() {
        EgressRelation r = EgressRelation.fromRow(row("42", "1700000000000", List.of(), List.of()));
        assertEquals("h1", r.host());
        assertEquals("api.example.com", r.dest());
        assertEquals("domain", r.destKind());
        assertEquals(42, r.events());
        assertEquals(1700000000000L, r.lastSeen());
    }

    @Test
    void 프로토콜은_l4_l7_를_합쳐_중복없이_정렬한다() {
        EgressRelation r = EgressRelation.fromRow(row("1", "1", List.of("tcp", "tcp"), List.of("tls")));
        assertEquals(List.of("tcp", "tls"), r.protocols());
    }

    @Test
    void 관측하지_못한_프로토콜은_빈_문자열로_오므로_버린다() {
        // 에이전트는 관측 못 한 값을 detail 에서 아예 뺀다. JSONExtractString 은 그걸 "" 로 준다.
        EgressRelation r = EgressRelation.fromRow(row("1", "1", List.of("", "udp"), List.of("")));
        assertEquals(List.of("udp"), r.protocols());
    }

    @Test
    void 프로토콜_칸이_아예_없어도_빈_목록으로_읽는다() {
        Map<String, Object> row = row("1", "1", null, null);
        row.remove("protocols");
        row.remove("l7Protocols");
        assertTrue(EgressRelation.fromRow(row).protocols().isEmpty());
    }

    @Test
    void 알림수_행과_severity_행도_문자열_숫자를_읽는다() {
        RelationAlertCount c = RelationAlertCount.fromRow(
                Map.of("host", "h1", "dest", "api.example.com", "alerts", "3"));
        assertEquals("h1", c.host());
        assertEquals("api.example.com", c.dest());
        assertEquals(3, c.alerts());

        HostRisk risk = HostRisk.fromRow(
                Map.of("host", "h1", "critical", "1", "high", "2", "medium", "0", "low", "0"));
        assertEquals("h1", risk.host());
        assertEquals(1, risk.critical());
        assertEquals(2, risk.high());
        assertEquals(3, risk.total());
    }
}
