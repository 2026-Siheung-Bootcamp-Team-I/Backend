package com.edrdog.apiservice.alert;

import com.edrdog.apiservice.alert.dto.Alert;
import com.edrdog.apiservice.alert.web.AlertResponse;
import com.edrdog.apiservice.auth.exception.AuthException;
import com.edrdog.apiservice.clickhouse.ClickHouseReader;
import com.edrdog.apiservice.query.ClickHouseQuery;
import com.edrdog.apiservice.query.EventQueryBuilder;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * AlertService 오케스트레이션 단위 검증(ClickHouse 없이 reader/writer/오버레이를 목으로).
 * 여기서 검증하는 건 앱 쪽 로직이다: 적재 위임, status 필터의 include/exclude id 계산, 오버레이 병합, 404 처리.
 * (실제 dedup·집계·격리 SQL 실행은 ClickHouse 몫이라 SQL 자체는 AlertQueryBuilderTest 가 검증한다.)
 */
class AlertServiceTest {

    private final AlertClickHouseWriter writer = mock(AlertClickHouseWriter.class);
    private final AlertStatusRepository statuses = mock(AlertStatusRepository.class);
    private final ClickHouseReader reader = mock(ClickHouseReader.class);

    private final AlertService service = new AlertService(writer, statuses, reader,
            new AlertQueryBuilder("edrdog.alerts"), new EventQueryBuilder("edrdog.events"),
            new LineageGraphBuilder());

    private static Alert alert(String tenantId, long ts) {
        return new Alert("h1", "RULE_A", "T1059", "HIGH", "notify", ts, List.of("m1"), tenantId);
    }

    private static Map<String, Object> row(String id, String tenant, String host, long ts) {
        return Map.of("id", id, "tenant_id", tenant, "host", host, "rule_id", "RULE_A",
                "mitre", "T1059", "severity", "HIGH", "action", "notify",
                "ts", String.valueOf(ts), "matched", List.of("m1"));
    }

    private static AlertStatusRecord triaged(String id, String tenant, String status) {
        return AlertStatusRecord.of(id, tenant, status, Instant.now());
    }

    // --- ingest ---

    @Test
    void ingest_는_결정적id로_writer에_위임한다() {
        service.ingest(alert("A", 100L));
        String expected = AlertId.of("A", "h1", "RULE_A", 100L);
        verify(writer).insert(eq(expected), any(Alert.class));
    }

    @Test
    void ingest_두번이면_writer도_두번_dedup은_CH몫() {
        service.ingest(alert("A", 100L));
        service.ingest(alert("A", 100L));
        verify(writer, times(2)).insert(any(), any());
    }

    @Test
    void ingest_tenant없으면_skip() {
        service.ingest(alert(null, 100L));
        service.ingest(alert("  ", 100L));
        verify(writer, never()).insert(any(), any());
    }

    // --- query: status 필터 -> include/exclude id, 병합 ---

    @Test
    void query_open_은_트리아지된id를_NOT_IN으로_넘기고_status는_open() {
        when(statuses.findByTenantId("A")).thenReturn(List.of(triaged("t1", "A", AlertStatus.CONFIRMED)));
        when(reader.query(any())).thenReturn(List.of(row("r1", "A", "h1", 100L)));
        when(statuses.findAllById(any())).thenReturn(List.of());

        List<AlertResponse> out = service.query("A", null, null, "open", null, null, null);

        ArgumentCaptor<ClickHouseQuery> cap = ArgumentCaptor.forClass(ClickHouseQuery.class);
        verify(reader).query(cap.capture());
        assertTrue(cap.getValue().sql().contains("id NOT IN"), cap.getValue().sql());
        assertEquals("t1", cap.getValue().params().get("exc0"));
        assertEquals(1, out.size());
        assertEquals(AlertStatus.OPEN, out.get(0).status());
    }

    @Test
    void query_confirmed_인데_트리아지가_없으면_CH조회없이_빈결과() {
        when(statuses.findByTenantId("A")).thenReturn(List.of());

        assertTrue(service.query("A", null, null, AlertStatus.CONFIRMED, null, null, null).isEmpty());
        verify(reader, never()).query(any());
    }

    @Test
    void query_confirmed_는_IN으로_좁히고_status를_병합한다() {
        when(statuses.findByTenantId("A")).thenReturn(List.of(triaged("r1", "A", AlertStatus.CONFIRMED)));
        when(reader.query(any())).thenReturn(List.of(row("r1", "A", "h1", 100L)));
        when(statuses.findAllById(any())).thenReturn(List.of(triaged("r1", "A", AlertStatus.CONFIRMED)));

        List<AlertResponse> out = service.query("A", null, null, AlertStatus.CONFIRMED, null, null, null);

        assertEquals(1, out.size());
        assertEquals(AlertStatus.CONFIRMED, out.get(0).status());
        assertEquals("RULE_A", out.get(0).ruleId());
    }

    // --- get ---

    @Test
    void get_없으면_404() {
        when(reader.query(any())).thenReturn(List.of());
        assertThrows(AuthException.class, () -> service.get("A", "nope"));
    }

    @Test
    void get_은_오버레이_status를_병합한다() {
        when(reader.query(any())).thenReturn(List.of(row("r1", "A", "h1", 100L)));
        when(statuses.findById("r1")).thenReturn(java.util.Optional.of(triaged("r1", "A", AlertStatus.FALSE_POSITIVE)));

        assertEquals(AlertStatus.FALSE_POSITIVE, service.get("A", "r1").status());
    }

    // --- triage ---

    @Test
    void triage_잘못된_status는_400_이고_CH조회도_안한다() {
        assertThrows(AuthException.class, () -> service.triage("A", "r1", "deleted"));
        verify(reader, never()).query(any());
        verify(statuses, never()).save(any());
    }

    @Test
    void triage_대상없으면_404_이고_오버레이_저장안함() {
        when(reader.query(any())).thenReturn(List.of());
        assertThrows(AuthException.class, () -> service.triage("A", "nope", AlertStatus.CONFIRMED));
        verify(statuses, never()).save(any());
    }

    @Test
    void triage_는_오버레이를_upsert하고_새_status를_반환한다() {
        when(reader.query(any())).thenReturn(List.of(row("r1", "A", "h1", 100L)));

        AlertResponse res = service.triage("A", "r1", AlertStatus.CONFIRMED);

        ArgumentCaptor<AlertStatusRecord> cap = ArgumentCaptor.forClass(AlertStatusRecord.class);
        verify(statuses).save(cap.capture());
        assertEquals("r1", cap.getValue().getId());
        assertEquals("A", cap.getValue().getTenantId());
        assertEquals(AlertStatus.CONFIRMED, cap.getValue().getStatus());
        assertEquals(AlertStatus.CONFIRMED, res.status());
    }

    // --- lineage ---

    @Test
    void lineage_대상없으면_404() {
        when(reader.query(any())).thenReturn(List.of());
        assertThrows(AuthException.class, () -> service.lineage("A", "nope"));
    }

    @Test
    void lineage_는_판정기록으로_host를_찾아_events를_그래프로_만든다() {
        // 첫 조회(byId)는 alerts 테이블, 둘째(lineage)는 events 테이블 -> SQL 로 라우팅한다.
        when(reader.query(any())).thenAnswer(inv -> {
            ClickHouseQuery q = inv.getArgument(0);
            if (q.sql().contains("edrdog.alerts")) {
                return List.of(row("r1", "A", "h1", 100L));
            }
            return List.of(
                    Map.of("type", "process", "ts", 100L, "process", "child.exe", "parent", "root.exe",
                            "dest_ip", "", "dest_port", 0),
                    Map.of("type", "network", "ts", 100L, "process", "child.exe", "parent", "",
                            "dest_ip", "10.0.0.9", "dest_port", 4444));
        });

        var graph = service.lineage("A", "r1");
        assertEquals(3, graph.nodes().size());
        assertEquals(2, graph.edges().size());
    }

    // --- summary / timeseries: CH 집계 행을 앱에서 조립하는 로직 ---

    @Test
    void summary_는_severity분포와_카테고리별_topThreats를_조립한다() {
        when(reader.query(any())).thenAnswer(inv -> {
            ClickHouseQuery q = inv.getArgument(0);
            if (q.sql().contains("GROUP BY severity")) {
                return List.of(Map.of("severity", "CRITICAL", "cnt", "1"),
                        Map.of("severity", "HIGH", "cnt", "2"));
            }
            return List.of(Map.of("rule_id", "DOWNLOAD_AND_EXECUTE", "cnt", "2"),
                    Map.of("rule_id", "SUSPICIOUS_PROCESS_CHAIN", "cnt", "1"));
        });

        var s = service.summary("A", null, null);
        assertEquals(3, s.total());
        assertEquals(1, s.severity().critical());
        assertEquals(2, s.severity().high());
        assertEquals(0, s.severity().medium());
        assertEquals(2, s.topThreats().size());
        assertEquals("악성코드", s.topThreats().get(0).category());
        assertEquals(2, s.topThreats().get(0).count());
        assertEquals("권한상승", s.topThreats().get(1).category());
    }

    @Test
    void timeseries_는_버킷별_severity를_묶고_빈버킷을_0으로_채운다() {
        when(reader.query(any())).thenReturn(List.of(
                Map.of("bucketStart", "0", "severity", "CRITICAL", "cnt", "1"),
                Map.of("bucketStart", "0", "severity", "HIGH", "cnt", "1"),
                Map.of("bucketStart", "3600000", "severity", "HIGH", "cnt", "1")));

        var buckets = service.timeseries("A", 0L, 7_200_000L, "hour");
        assertEquals(2, buckets.size());
        assertEquals(1, buckets.get(0).critical());
        assertEquals(1, buckets.get(0).high());
        assertEquals(2, buckets.get(0).count());
        assertEquals(1, buckets.get(1).high());
        assertEquals(1, buckets.get(1).count());
    }
}
