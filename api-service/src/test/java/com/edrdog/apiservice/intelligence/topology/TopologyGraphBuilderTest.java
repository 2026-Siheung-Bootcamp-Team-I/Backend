package com.edrdog.apiservice.intelligence.topology;

import com.edrdog.apiservice.intelligence.topology.web.TopologyEdge;
import com.edrdog.apiservice.intelligence.topology.web.TopologyNode;
import com.edrdog.apiservice.intelligence.topology.web.TopologyResponse;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 관계 집계 행을 그래프(노드/엣지)로 조립하는 순수 로직 검증.
 * 관측하지 않은 것을 채우지 않는지(그룹 없는 목적지, 알림 없는 관계)와
 * Top-N 으로 자른 사실이 응답에 드러나는지를 본다.
 */
class TopologyGraphBuilderTest {

    private static EgressRelation rel(String host, String dest, String destKind, long events) {
        return new EgressRelation(host, dest, destKind, events, 5000L, List.of("tcp"));
    }

    private static TopologyNode node(TopologyResponse res, String id) {
        return res.nodes().stream().filter(n -> n.id().equals(id)).findFirst().orElse(null);
    }

    // --- 노드/엣지 조립 ---

    @Test
    void 엔드포인트와_목적지가_노드가_되고_엣지로_이어진다() {
        TopologyResponse res = TopologyGraphBuilder.build(1000L, 2000L, 1,
                List.of(rel("h1", "api.example.com", "domain", 7)), List.of(), List.of());

        assertEquals(1000L, res.from());
        assertEquals(2000L, res.to());
        assertNotNull(node(res, "host:h1"));
        assertEquals("endpoint", node(res, "host:h1").kind());
        assertEquals("h1", node(res, "host:h1").label());
        assertNotNull(node(res, "dest:api.example.com"));
        assertEquals("destination", node(res, "dest:api.example.com").kind());
        assertEquals("domain", node(res, "dest:api.example.com").destKind());

        assertEquals(1, res.edges().size());
        TopologyEdge e = res.edges().get(0);
        assertEquals("host:h1", e.from());
        assertEquals("dest:api.example.com", e.to());
        assertEquals(7, e.events());
    }

    @Test
    void 같은_호스트가_여러_관계를_가져도_노드는_하나다() {
        TopologyResponse res = TopologyGraphBuilder.build(1000L, 2000L, 2,
                List.of(rel("h1", "a.example.com", "domain", 3), rel("h1", "10.0.0.9", "ip", 2)),
                List.of(), List.of());

        assertEquals(1, res.nodes().stream().filter(n -> n.kind().equals("endpoint")).count());
        assertEquals(2, res.edges().size());
    }

    @Test
    void 같은_목적지를_여러_호스트가_보면_목적지_노드는_하나다() {
        TopologyResponse res = TopologyGraphBuilder.build(1000L, 2000L, 2,
                List.of(rel("h1", "api.example.com", "domain", 3), rel("h2", "api.example.com", "domain", 2)),
                List.of(), List.of());

        assertEquals(1, res.nodes().stream().filter(n -> n.kind().equals("destination")).count());
        assertEquals(2, res.edges().size());
    }

    @Test
    void 엣지는_받은_순서를_유지한다() {
        TopologyResponse res = TopologyGraphBuilder.build(1000L, 2000L, 2,
                List.of(rel("h1", "big.example.com", "domain", 9), rel("h1", "small.example.com", "domain", 1)),
                List.of(), List.of());

        assertEquals("dest:big.example.com", res.edges().get(0).to());
        assertEquals("dest:small.example.com", res.edges().get(1).to());
    }

    @Test
    void 엣지에_프로토콜_라벨과_최신_관측시각이_실린다() {
        TopologyResponse res = TopologyGraphBuilder.build(1000L, 2000L, 1,
                List.of(new EgressRelation("h1", "api.example.com", "domain", 4, 1900L, List.of("tcp", "tls"))),
                List.of(), List.of());

        assertEquals(List.of("tcp", "tls"), res.edges().get(0).protocols());
        assertEquals(1900L, res.edges().get(0).lastSeen());
    }

    @Test
    void 프로토콜을_관측하지_못했으면_비운다() {
        TopologyResponse res = TopologyGraphBuilder.build(1000L, 2000L, 1,
                List.of(new EgressRelation("h1", "10.0.0.9", "ip", 4, 1900L, List.of())),
                List.of(), List.of());

        assertTrue(res.edges().get(0).protocols().isEmpty());
    }

    // --- 관계별 알림 수 ---

    @Test
    void 알림이_있는_관계에만_알림수가_붙는다() {
        TopologyResponse res = TopologyGraphBuilder.build(1000L, 2000L, 2,
                List.of(rel("h1", "bad.example.com", "domain", 3), rel("h1", "ok.example.com", "domain", 2)),
                List.of(new RelationAlertCount("h1", "bad.example.com", 2)), List.of());

        assertEquals(2, res.edges().get(0).alerts());
        assertEquals(0, res.edges().get(1).alerts());
    }

    @Test
    void 알림수는_host_와_목적지가_모두_같아야_붙는다() {
        TopologyResponse res = TopologyGraphBuilder.build(1000L, 2000L, 1,
                List.of(rel("h1", "bad.example.com", "domain", 3)),
                List.of(new RelationAlertCount("h2", "bad.example.com", 5)), List.of());

        assertEquals(0, res.edges().get(0).alerts());
    }

    // --- 도메인 그룹 ---

    @Test
    void 같은_등록가능_도메인을_쓰는_서브도메인은_그룹으로_묶인다() {
        TopologyResponse res = TopologyGraphBuilder.build(1000L, 2000L, 2,
                List.of(rel("h1", "api.example.co.kr", "domain", 3), rel("h1", "cdn.example.co.kr", "domain", 2)),
                List.of(), List.of());

        TopologyNode group = node(res, "group:example.co.kr");
        assertNotNull(group);
        assertEquals("domainGroup", group.kind());
        assertEquals("example.co.kr", group.label());
        assertEquals(2, group.members());
        assertEquals("group:example.co.kr", node(res, "dest:api.example.co.kr").group());
        assertEquals("group:example.co.kr", node(res, "dest:cdn.example.co.kr").group());
    }

    @Test
    void 목적지가_하나뿐인_등록가능_도메인은_묶지_않는다() {
        // 원소가 하나인 묶음은 화면에 상자만 늘리고 알려주는 것이 없다.
        TopologyResponse res = TopologyGraphBuilder.build(1000L, 2000L, 1,
                List.of(rel("h1", "api.example.com", "domain", 3)), List.of(), List.of());

        assertNull(node(res, "group:example.com"));
        assertNull(node(res, "dest:api.example.com").group());
    }

    @Test
    void IP_목적지는_그룹을_만들지_않는다() {
        TopologyResponse res = TopologyGraphBuilder.build(1000L, 2000L, 2,
                List.of(rel("h1", "10.0.0.9", "ip", 3), rel("h1", "10.0.0.10", "ip", 2)), List.of(), List.of());

        assertFalse(res.nodes().stream().anyMatch(n -> n.kind().equals("domainGroup")));
        assertNull(node(res, "dest:10.0.0.9").group());
    }

    @Test
    void 등록가능_도메인_자신과_서브도메인도_같은_그룹이다() {
        TopologyResponse res = TopologyGraphBuilder.build(1000L, 2000L, 2,
                List.of(rel("h1", "example.com", "domain", 3), rel("h1", "api.example.com", "domain", 2)),
                List.of(), List.of());

        assertEquals(2, node(res, "group:example.com").members());
        assertEquals("group:example.com", node(res, "dest:example.com").group());
    }

    // --- 잘림 표시 ---

    @Test
    void Top_N_으로_잘리면_전체수와_함께_잘렸다고_알린다() {
        TopologyResponse res = TopologyGraphBuilder.build(1000L, 2000L, 137,
                List.of(rel("h1", "a.example.com", "domain", 3), rel("h1", "b.example.com", "domain", 2)),
                List.of(), List.of());

        assertEquals(137, res.totalRelations());
        assertEquals(2, res.shownRelations());
        assertTrue(res.truncated());
    }

    @Test
    void 다_보여주면_잘리지_않았다고_알린다() {
        TopologyResponse res = TopologyGraphBuilder.build(1000L, 2000L, 1,
                List.of(rel("h1", "a.example.com", "domain", 3)), List.of(), List.of());

        assertEquals(1, res.totalRelations());
        assertEquals(1, res.shownRelations());
        assertFalse(res.truncated());
    }

    // --- 위험 점수 ---

    @Test
    void 엔드포인트에_위험점수와_열린알림수가_붙는다() {
        TopologyResponse res = TopologyGraphBuilder.build(1000L, 2000L, 1,
                List.of(rel("h1", "a.example.com", "domain", 3)),
                List.of(), List.of(new HostRisk("h1", 1, 2, 0, 0)));

        assertEquals(RiskScore.of(1, 2, 0, 0), node(res, "host:h1").riskScore());
        assertEquals(3, node(res, "host:h1").openAlerts());
    }

    @Test
    void 알림이_없는_엔드포인트는_0점이다() {
        TopologyResponse res = TopologyGraphBuilder.build(1000L, 2000L, 1,
                List.of(rel("h1", "a.example.com", "domain", 3)), List.of(), List.of());

        assertEquals(0, node(res, "host:h1").riskScore());
        assertEquals(0, node(res, "host:h1").openAlerts());
    }

    @Test
    void 관계가_없으면_빈_그래프를_준다() {
        TopologyResponse res = TopologyGraphBuilder.build(1000L, 2000L, 0, List.of(), List.of(), List.of());

        assertTrue(res.nodes().isEmpty());
        assertTrue(res.edges().isEmpty());
        assertFalse(res.truncated());
    }
}
