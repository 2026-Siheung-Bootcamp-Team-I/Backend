package com.edrdog.apiservice.host;

import com.edrdog.apiservice.alert.HostAlertCount;
import com.edrdog.apiservice.host.web.HostResponse;
import com.edrdog.apiservice.host.web.HostSummary;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * events 행, alert 집계, 등록 노드(agent_nodes)를 host 기준으로 병합하는 순수 로직 검증.
 * 호스트 집합은 events ∪ 등록 노드다(이벤트가 없어도 등록만 됐으면 목록에 나와야 한다).
 * 위협수는 alert 집계에서, status 와 위험 점수는 severity 분포 하나에서 같이 나온다.
 */
class HostAggregatorTest {

    /** ClickHouse 응답 한 행(host, last_seen). last_seen 은 UInt64 라 문자열로 온다. */
    private static Map<String, Object> row(String host, String lastSeen) {
        return Map.of("host", host, "last_seen", lastSeen);
    }

    /** host 별 열린 alert 집계 값. */
    private static HostAlertCount count(String host, long total, long critical, long high) {
        return new HostAlertCount(host, total, critical, high);
    }

    /** host 별 열린 alert severity 분포(위험 점수 재료). */
    private static HostRisk risk(String host, long critical, long high, long medium, long low) {
        return new HostRisk(host, critical, high, medium, low);
    }

    /** agent_nodes 등록 노드 값(host, agentSeen). platform 은 기본 darwin. */
    private static EnrolledHost enrolled(String host, long agentSeen) {
        return new EnrolledHost(host, agentSeen, "darwin");
    }

    @Test
    void alert_없는_host_는_정상_위협0() {
        List<HostResponse> hosts = HostAggregator.hosts(
                List.of(row("h1", "1000")), List.of(), List.of(), List.of());

        assertEquals(1, hosts.size());
        HostResponse h = hosts.get(0);
        assertEquals("h1", h.host());
        assertEquals(1000L, h.lastSeen());
        assertEquals(HostStatus.HEALTHY, h.status());
        assertEquals(0L, h.threats());
    }

    @Test
    void 열린_CRITICAL_있는_host_는_위험_위협수는_열린총수() {
        List<HostResponse> hosts = HostAggregator.hosts(
                List.of(row("h1", "1000")),
                List.of(count("h1", 3, 1, 2)), List.of(risk("h1", 1, 2, 0, 0)), List.of());

        HostResponse h = hosts.get(0);
        assertEquals(HostStatus.CRITICAL, h.status());
        assertEquals(3L, h.threats());
    }

    @Test
    void HIGH만_있는_host_는_주의() {
        List<HostResponse> hosts = HostAggregator.hosts(
                List.of(row("h1", "1000")),
                List.of(count("h1", 2, 0, 2)), List.of(risk("h1", 0, 2, 0, 0)), List.of());

        assertEquals(HostStatus.WARNING, hosts.get(0).status());
        assertEquals(2L, hosts.get(0).threats());
    }

    @Test
    void MEDIUM_만_쌓인_host_는_점수를_따라_위험이다() {
        // 열린 MEDIUM 54건이면 점수가 상한 100 인데, 예전 분류는 MEDIUM 을 보지 않아 "정상"으로 떴다.
        List<HostResponse> hosts = HostAggregator.hosts(
                List.of(row("h1", "1000")),
                List.of(count("h1", 54, 0, 0)), List.of(risk("h1", 0, 0, 54, 0)), List.of());

        HostResponse h = hosts.get(0);
        assertEquals(100, h.riskScore());
        assertEquals(HostStatus.CRITICAL, h.status());
    }

    // --- 위험 점수 ---

    @Test
    void 위험점수는_severity_분포를_RiskScore_로_환산해_붙는다() {
        List<HostResponse> hosts = HostAggregator.hosts(
                List.of(row("h1", "1000")),
                List.of(count("h1", 6, 1, 2)), List.of(risk("h1", 1, 2, 3, 0)), List.of());

        assertEquals(RiskScore.of(1, 2, 3, 0), hosts.get(0).riskScore());
    }

    @Test
    void 알림이_없는_host_는_점수가_0_이다() {
        // 0 은 "관측하지 못했다" 가 아니라 "열린 알림이 없다" 는 관측 결과다.
        List<HostResponse> hosts = HostAggregator.hosts(
                List.of(row("h1", "1000")), List.of(), List.of(), List.of());

        assertEquals(0, hosts.get(0).riskScore());
    }

    @Test
    void 등록만_되고_events_없는_host_도_점수가_0_이다() {
        List<HostResponse> hosts = HostAggregator.hosts(
                List.of(), List.of(), List.of(), List.of(enrolled("h-new", 7000)));

        assertEquals(0, hosts.get(0).riskScore());
    }

    @Test
    void 다른_host_의_severity_분포는_섞이지_않는다() {
        List<HostResponse> hosts = HostAggregator.hosts(
                List.of(row("h1", "2000"), row("h2", "1000")),
                List.of(), List.of(risk("h1", 4, 0, 0, 0)), List.of());

        assertEquals(RiskScore.of(4, 0, 0, 0), hosts.get(0).riskScore());
        assertEquals(0, hosts.get(1).riskScore());
    }

    @Test
    void events_순서를_그대로_유지한다() {
        List<HostResponse> hosts = HostAggregator.hosts(
                List.of(row("h2", "3000"), row("h1", "1000")),
                List.of(count("h1", 1, 1, 0)), List.of(), List.of());

        assertEquals("h2", hosts.get(0).host());
        assertEquals("h1", hosts.get(1).host());
    }

    @Test
    void alert만_있고_events_없는_host_는_목록에_없다() {
        List<HostResponse> hosts = HostAggregator.hosts(
                List.of(row("h1", "1000")),
                List.of(count("ghost", 5, 5, 0)), List.of(), List.of());

        assertEquals(1, hosts.size());
        assertEquals("h1", hosts.get(0).host());
    }

    @Test
    void events만_있고_등록이_없으면_enrolled_false_agentSeen_0() {
        List<HostResponse> hosts = HostAggregator.hosts(
                List.of(row("h1", "1000")), List.of(), List.of(), List.of());

        HostResponse h = hosts.get(0);
        assertFalse(h.enrolled());
        assertEquals(0L, h.agentSeen());
    }

    @Test
    void events와_등록이_둘다_있으면_enrolled_true_lastSeen과_agentSeen_모두_채워짐() {
        List<HostResponse> hosts = HostAggregator.hosts(
                List.of(row("h1", "1000")), List.of(), List.of(),
                List.of(enrolled("h1", 5000)));

        HostResponse h = hosts.get(0);
        assertEquals("h1", h.host());
        assertEquals(1000L, h.lastSeen());
        assertTrue(h.enrolled());
        assertEquals(5000L, h.agentSeen());
    }

    @Test
    void 등록만_있고_events_없으면_lastSeen0_enrolled_true_agentSeen_채워져_목록에_포함() {
        List<HostResponse> hosts = HostAggregator.hosts(
                List.of(), List.of(), List.of(), List.of(enrolled("h-new", 7000)));

        assertEquals(1, hosts.size());
        HostResponse h = hosts.get(0);
        assertEquals("h-new", h.host());
        assertEquals(0L, h.lastSeen());
        assertEquals(0L, h.threats());
        assertEquals(HostStatus.HEALTHY, h.status());
        assertTrue(h.enrolled());
        assertEquals(7000L, h.agentSeen());
    }

    @Test
    void host_이름_대소문자가_달라도_같은_기기로_합쳐진다() {
        List<HostResponse> hosts = HostAggregator.hosts(
                List.of(row("DESKTOP-ABC", "1000")), List.of(), List.of(),
                List.of(enrolled("desktop-abc", 5000)));

        assertEquals(1, hosts.size());
        HostResponse h = hosts.get(0);
        // 표시 이름은 events 쪽 원본을 우선한다.
        assertEquals("DESKTOP-ABC", h.host());
        assertTrue(h.enrolled());
        assertEquals(5000L, h.agentSeen());
    }

    @Test
    void 등록된_host_는_platform_이_실린다() {
        List<HostResponse> hosts = HostAggregator.hosts(
                List.of(row("h1", "1000")), List.of(), List.of(),
                List.of(new EnrolledHost("h1", 5000, "windows")));

        assertEquals("windows", hosts.get(0).platform());
    }

    @Test
    void 미등록_host_의_platform_은_빈문자열() {
        List<HostResponse> hosts = HostAggregator.hosts(
                List.of(row("h1", "1000")), List.of(), List.of(), List.of());

        assertEquals("", hosts.get(0).platform());
    }

    @Test
    void 등록만_있고_events_없는_host_도_platform_이_실린다() {
        List<HostResponse> hosts = HostAggregator.hosts(
                List.of(), List.of(), List.of(), List.of(new EnrolledHost("h-new", 7000, "darwin")));

        assertEquals("darwin", hosts.get(0).platform());
    }

    @Test
    void 정렬은_events_있는_host가_앞이고_등록만_있는_host는_agentSeen_DESC로_뒤에_붙는다() {
        List<HostResponse> hosts = HostAggregator.hosts(
                List.of(row("h2", "3000"), row("h1", "1000")), List.of(), List.of(),
                List.of(enrolled("h-old", 100), enrolled("h-new", 9000)));

        assertEquals(4, hosts.size());
        assertEquals("h2", hosts.get(0).host());
        assertEquals("h1", hosts.get(1).host());
        assertEquals("h-new", hosts.get(2).host());
        assertEquals("h-old", hosts.get(3).host());
    }

    @Test
    void 요약은_status별_수와_총수를_센다() {
        List<HostResponse> hosts = List.of(
                new HostResponse("h1", 1, HostStatus.CRITICAL, 2, 0, true, 1, ""),
                new HostResponse("h2", 1, HostStatus.WARNING, 1, 0, false, 0, ""),
                new HostResponse("h3", 1, HostStatus.HEALTHY, 0, 0, false, 0, ""),
                new HostResponse("h4", 1, HostStatus.HEALTHY, 0, 0, true, 1, ""));

        HostSummary s = HostAggregator.summary(hosts);
        assertEquals(2L, s.healthy());
        assertEquals(1L, s.warning());
        assertEquals(1L, s.critical());
        assertEquals(4L, s.total());
        assertEquals(0L, s.noEvents());
    }

    @Test
    void 빈_목록_요약은_전부_0() {
        HostSummary s = HostAggregator.summary(List.of());
        assertEquals(0L, s.healthy());
        assertEquals(0L, s.warning());
        assertEquals(0L, s.critical());
        assertEquals(0L, s.total());
        assertEquals(0L, s.noEvents());
    }

    @Test
    void 수집없는_등록기기는_healthy가_아니라_noEvents로_잡힌다() {
        // 등록만 되고 이벤트가 한 번도 없는 기기(lastSeen=0, enrolled=true)는 "정상"이 아니라 "아직 모름"이다.
        List<HostResponse> hosts = List.of(
                new HostResponse("h-new", 0, HostStatus.HEALTHY, 0, 0, true, 5000, ""));

        HostSummary s = HostAggregator.summary(hosts);
        assertEquals(0L, s.healthy());
        assertEquals(1L, s.noEvents());
        assertEquals(1L, s.total());
    }

    @Test
    void 이벤트있는_정상기기는_그대로_healthy로_잡힌다() {
        List<HostResponse> hosts = List.of(
                new HostResponse("h1", 1000, HostStatus.HEALTHY, 0, 0, true, 1000, ""));

        HostSummary s = HostAggregator.summary(hosts);
        assertEquals(1L, s.healthy());
        assertEquals(0L, s.noEvents());
    }

    @Test
    void healthy_warning_critical_noEvents_합은_total과_같다() {
        List<HostResponse> hosts = List.of(
                new HostResponse("h1", 1000, HostStatus.CRITICAL, 1, 0, true, 1000, ""),
                new HostResponse("h2", 1000, HostStatus.WARNING, 1, 0, false, 0, ""),
                new HostResponse("h3", 1000, HostStatus.HEALTHY, 0, 0, false, 0, ""),
                new HostResponse("h4", 0, HostStatus.HEALTHY, 0, 0, true, 5000, ""),
                new HostResponse("h5", 0, HostStatus.HEALTHY, 0, 0, true, 3000, ""));

        HostSummary s = HostAggregator.summary(hosts);
        assertEquals(5L, s.total());
        assertEquals(s.total(), s.healthy() + s.warning() + s.critical() + s.noEvents());
        assertEquals(2L, s.noEvents());
        assertEquals(1L, s.healthy());
    }
}
