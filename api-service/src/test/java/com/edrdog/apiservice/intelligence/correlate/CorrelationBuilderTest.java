package com.edrdog.apiservice.intelligence.correlate;

import com.edrdog.apiservice.event.EventResponse;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static com.edrdog.apiservice.intelligence.correlate.TestEvents.dns;
import static com.edrdog.apiservice.intelligence.correlate.TestEvents.l7;
import static com.edrdog.apiservice.intelligence.correlate.TestEvents.network;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 관계 그래프 조립(순수) 검증.
 *
 * 가장 중요한 것은 출처 구분이다. 관측(OBSERVED)·추론(INFERRED)·실시간 조회(LIVE_DNS)가
 * 같은 자리에 섞여 나가면 이 API 는 오히려 잘못된 결론을 돕는 도구가 된다.
 */
class CorrelationBuilderTest {

    private static final long T = 1_700_000_000_000L;
    private static final CorrelateTarget DOMAIN_SEED = new CorrelateTarget(TargetKind.DOMAIN, "example.com");
    private static final CorrelateTarget IP_SEED = new CorrelateTarget(TargetKind.IP, "93.184.216.34");

    @Test
    void DNS_응답의_answers_는_도메인에서_IP_로_가는_관측_관계가_된다() {
        EventResponse d = dns("mac-1", T, "example.com", "", List.of("93.184.216.34", "93.184.216.35"));

        CorrelationGraph g = build(List.of(CorrelatedEvent.observed(d)));

        CorrelationEdge e = edge(g, "domain:example.com", "ip:93.184.216.34", RelationType.RESOLVED_TO);
        assertEquals(RelationOrigin.OBSERVED, e.origin());
        assertEquals(1, e.observations());
        assertEquals(T, e.firstSeen());
        assertEquals(T, e.lastSeen());
        assertNull(e.basis());
        assertTrue(has(g, "domain:example.com", "ip:93.184.216.35", RelationType.RESOLVED_TO));
    }

    @Test
    void answers_에_IP_가_아닌_별칭이_섞이면_IP_로_두지_않는다() {
        // Windows(ETW)의 QueryResults 에는 CNAME 이 섞여 온다. 그걸 IP 노드로 만들면 없는 IP 를 지어내는 셈이다.
        EventResponse d = dns("win-1", T, "example.com", "chrome.exe", List.of("cdn.example.net", "93.184.216.34"));

        CorrelationGraph g = build(List.of(CorrelatedEvent.observed(d)));

        assertTrue(has(g, "domain:example.com", "domain:cdn.example.net", RelationType.ALIAS_OF));
        assertTrue(has(g, "domain:example.com", "ip:93.184.216.34", RelationType.RESOLVED_TO));
        assertTrue(g.nodes().stream().noneMatch(n -> n.id().equals("ip:cdn.example.net")));
    }

    @Test
    void DNS_이벤트는_어떤_호스트가_물었는지도_준다() {
        EventResponse d = dns("mac-1", T, "example.com", "", List.of("93.184.216.34"));

        CorrelationGraph g = build(List.of(CorrelatedEvent.observed(d)));

        assertEquals(RelationOrigin.OBSERVED,
                edge(g, "host:mac-1", "domain:example.com", RelationType.QUERIED).origin());
    }

    @Test
    void 관측된_프로세스는_OBSERVED_로_나간다() {
        EventResponse d = dns("win-1", T, "example.com", "chrome.exe", List.of("93.184.216.34"));

        CorrelationGraph g = build(List.of(CorrelatedEvent.observed(d)));

        assertEquals(RelationOrigin.OBSERVED,
                edge(g, "process:chrome.exe", "domain:example.com", RelationType.QUERIED).origin());
    }

    @Test
    void 되짚어_찾은_프로세스는_INFERRED_로_나가고_근거를_단다() {
        EventResponse d = dns("mac-1", T, "example.com", "", List.of("93.184.216.34"));
        CorrelatedEvent ce = new CorrelatedEvent(d, "firefox", "network 이벤트 dest_ip=93.184.216.34");

        CorrelationGraph g = build(List.of(ce));

        CorrelationEdge e = edge(g, "process:firefox", "domain:example.com", RelationType.QUERIED);
        assertEquals(RelationOrigin.INFERRED, e.origin());
        assertEquals("network 이벤트 dest_ip=93.184.216.34", e.basis());
    }

    @Test
    void 되짚어도_못_찾으면_프로세스_관계를_만들지_않는다() {
        EventResponse d = dns("mac-1", T, "example.com", "", List.of("93.184.216.34"));

        CorrelationGraph g = build(List.of(CorrelatedEvent.observed(d)));

        assertTrue(g.nodes().stream().noneMatch(n -> n.kind() == NodeKind.PROCESS));
    }

    @Test
    void l7_이벤트는_도메인이_실제로_쓴_목적지_IP_를_잇는다() {
        EventResponse e = l7("mac-1", T, "93.184.216.34", "example.com", "curl");

        CorrelationGraph g = build(List.of(CorrelatedEvent.observed(e)));

        assertEquals(RelationOrigin.OBSERVED,
                edge(g, "domain:example.com", "ip:93.184.216.34", RelationType.CONNECTED_VIA).origin());
        assertTrue(has(g, "host:mac-1", "domain:example.com", RelationType.CONNECTED));
        assertTrue(has(g, "process:curl", "domain:example.com", RelationType.CONNECTED));
    }

    @Test
    void 도메인이_없는_network_이벤트는_IP_를_대상으로_잇는다() {
        EventResponse e = network("mac-1", T, "93.184.216.34", "curl");

        CorrelationGraph g = buildFor(IP_SEED, List.of(CorrelatedEvent.observed(e)), null, null);

        assertTrue(has(g, "host:mac-1", "ip:93.184.216.34", RelationType.CONNECTED));
        assertTrue(has(g, "process:curl", "ip:93.184.216.34", RelationType.CONNECTED));
    }

    @Test
    void 같은_관계가_여러_번_관측되면_한_줄로_합치고_횟수와_기간을_센다() {
        List<CorrelatedEvent> events = List.of(
                CorrelatedEvent.observed(dns("mac-1", T, "example.com", "", List.of("93.184.216.34"))),
                CorrelatedEvent.observed(dns("mac-1", T + 5_000, "example.com", "", List.of("93.184.216.34"))),
                CorrelatedEvent.observed(dns("mac-1", T + 1_000, "example.com", "", List.of("93.184.216.34"))));

        CorrelationEdge e = edge(build(events), "domain:example.com", "ip:93.184.216.34", RelationType.RESOLVED_TO);

        assertEquals(3, e.observations());
        assertEquals(T, e.firstSeen());
        assertEquals(T + 5_000, e.lastSeen());
    }

    @Test
    void 출처가_다르면_같은_두_점_사이라도_따로_센다() {
        // 관측으로도 나오고 지금 물어봐도 같은 IP 가 나오는 흔한 경우. 합치면 구분이 사라진다.
        EventResponse d = dns("mac-1", T, "example.com", "", List.of("93.184.216.34"));

        CorrelationGraph g = buildFor(DOMAIN_SEED, List.of(CorrelatedEvent.observed(d)),
                ForwardLookup.ok(List.of("93.184.216.34")), null);

        assertEquals(RelationOrigin.OBSERVED,
                edge(g, "domain:example.com", "ip:93.184.216.34", RelationType.RESOLVED_TO, RelationOrigin.OBSERVED)
                        .origin());
        assertEquals(RelationOrigin.LIVE_DNS,
                edge(g, "domain:example.com", "ip:93.184.216.34", RelationType.RESOLVED_TO, RelationOrigin.LIVE_DNS)
                        .origin());
    }

    @Test
    void 실시간_조회_관계는_관측_횟수를_갖지_않는다() {
        CorrelationGraph g = buildFor(DOMAIN_SEED, List.of(), ForwardLookup.ok(List.of("1.2.3.4")), null);

        CorrelationEdge e = edge(g, "domain:example.com", "ip:1.2.3.4", RelationType.RESOLVED_TO);
        assertEquals(RelationOrigin.LIVE_DNS, e.origin());
        assertEquals(0, e.observations());
        assertNull(e.firstSeen());
        assertNull(e.lastSeen());
    }

    @Test
    void PTR_이름은_도메인이_아니라_후보_노드로_붙는다() {
        // PTR 은 IP 소유자가 아무 이름이나 적을 수 있어 검증된 이름이 아니다. 원본 IP 를 대체해서는 안 된다.
        CorrelationGraph g = buildFor(IP_SEED, List.of(), null, ReverseLookup.ok(List.of("example.com")));

        CorrelationEdge e = edge(g, "ip:93.184.216.34", "ptr_name:example.com", RelationType.PTR_CANDIDATE);
        assertEquals(RelationOrigin.LIVE_DNS, e.origin());
        assertEquals(NodeKind.PTR_NAME, node(g, "ptr_name:example.com").kind());
        // 같은 문자열이어도 관측된 도메인 노드와 절대 합쳐지지 않는다.
        assertTrue(g.nodes().stream().noneMatch(n -> n.id().equals("domain:example.com")));
    }

    @Test
    void 조회가_실패하면_관계를_만들지_않는다() {
        // 실패는 "없다"가 아니다. 없는 것처럼 그리면 그것도 지어내는 것이다.
        CorrelationGraph g = buildFor(DOMAIN_SEED, List.of(), ForwardLookup.failed("timeout"), null);

        assertTrue(g.edges().isEmpty());
    }

    @Test
    void 관측이_한_건도_없어도_기준점_노드는_남는다() {
        CorrelationGraph g = build(List.of());

        assertEquals(1, g.nodes().size());
        assertEquals("domain:example.com", g.nodes().get(0).id());
        assertTrue(g.edges().isEmpty());
    }

    // --- helpers ---

    private static CorrelationGraph build(List<CorrelatedEvent> events) {
        return buildFor(DOMAIN_SEED, events, null, null);
    }

    private static CorrelationGraph buildFor(CorrelateTarget seed, List<CorrelatedEvent> events,
                                             ForwardLookup forward, ReverseLookup reverse) {
        return CorrelationBuilder.build(seed, events, forward, reverse);
    }

    private static boolean has(CorrelationGraph g, String from, String to, RelationType relation) {
        return find(g, from, to, relation, null).isPresent();
    }

    private static CorrelationEdge edge(CorrelationGraph g, String from, String to, RelationType relation) {
        return find(g, from, to, relation, null)
                .orElseThrow(() -> new AssertionError("엣지 없음: " + from + " -> " + to + " " + relation
                        + " / 실제: " + g.edges()));
    }

    private static CorrelationEdge edge(CorrelationGraph g, String from, String to, RelationType relation,
                                        RelationOrigin origin) {
        return find(g, from, to, relation, origin)
                .orElseThrow(() -> new AssertionError("엣지 없음: " + from + " -> " + to + " " + relation + " " + origin
                        + " / 실제: " + g.edges()));
    }

    private static Optional<CorrelationEdge> find(CorrelationGraph g, String from, String to,
                                                  RelationType relation, RelationOrigin origin) {
        return g.edges().stream()
                .filter(e -> e.from().equals(from) && e.to().equals(to) && e.relation() == relation)
                .filter(e -> origin == null || e.origin() == origin)
                .findFirst();
    }

    private static CorrelationNode node(CorrelationGraph g, String id) {
        return g.nodes().stream().filter(n -> n.id().equals(id)).findFirst()
                .orElseThrow(() -> new AssertionError("노드 없음: " + id + " / 실제: " + g.nodes()));
    }
}
