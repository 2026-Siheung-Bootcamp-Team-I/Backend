package com.edrdog.apiservice.alert;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * AlertRepository 슬라이스(H2). tenant 격리 + host/severity/status/시간범위 필터 + ts DESC + limit 확인.
 */
@DataJpaTest
class AlertRepositoryTest {

    @Autowired
    private AlertRepository alerts;

    private void seed(String tenantId, String host, String severity, String status, long ts) {
        String id = AlertId.of(tenantId, host, "RULE_" + ts, ts);
        AlertRecord r = AlertRecord.open(id, tenantId, host, "RULE_" + ts, "T1059",
                severity, "notify", ts, List.of("m1"), Instant.now());
        if (!status.equals(AlertStatus.OPEN)) {
            r.triage(status, Instant.now());
        }
        alerts.save(r);
    }

    private static Pageable page(int limit) {
        return PageRequest.of(0, limit);
    }

    @Test
    void tenant_격리_다른조직_것은_안보인다() {
        seed("A", "h1", "HIGH", AlertStatus.OPEN, 100L);
        seed("B", "h1", "HIGH", AlertStatus.OPEN, 200L);

        List<AlertRecord> a = alerts.search("A", null, null, null, null, null, page(10));
        assertEquals(1, a.size());
        assertEquals("A", a.get(0).getTenantId());
    }

    @Test
    void host_severity_status_필터() {
        seed("A", "h1", "HIGH", AlertStatus.OPEN, 100L);
        seed("A", "h2", "CRITICAL", AlertStatus.CONFIRMED, 200L);

        assertEquals(1, alerts.search("A", "h1", null, null, null, null, page(10)).size());
        assertEquals(1, alerts.search("A", null, "CRITICAL", null, null, null, page(10)).size());
        assertEquals(1, alerts.search("A", null, null, AlertStatus.CONFIRMED, null, null, page(10)).size());
        assertTrue(alerts.search("A", "none", null, null, null, null, page(10)).isEmpty());
    }

    @Test
    void 시간범위_필터() {
        seed("A", "h1", "HIGH", AlertStatus.OPEN, 100L);
        seed("A", "h1", "HIGH", AlertStatus.OPEN, 300L);

        assertEquals(1, alerts.search("A", null, null, null, 200L, null, page(10)).size());
        assertEquals(1, alerts.search("A", null, null, null, null, 200L, page(10)).size());
        assertEquals(2, alerts.search("A", null, null, null, 100L, 300L, page(10)).size());
    }

    @Test
    void ts_내림차순_그리고_limit() {
        seed("A", "h1", "HIGH", AlertStatus.OPEN, 100L);
        seed("A", "h1", "HIGH", AlertStatus.OPEN, 300L);
        seed("A", "h1", "HIGH", AlertStatus.OPEN, 200L);

        List<AlertRecord> all = alerts.search("A", null, null, null, null, null, page(10));
        assertEquals(300L, all.get(0).getTs());
        assertEquals(200L, all.get(1).getTs());
        assertEquals(100L, all.get(2).getTs());

        List<AlertRecord> limited = alerts.search("A", null, null, null, null, null, page(2));
        assertEquals(2, limited.size());
        assertEquals(300L, limited.get(0).getTs());
    }

    // --- host 별 열린 alert 집계 ---

    private static HostAlertCount find(List<HostAlertCount> counts, String host) {
        return counts.stream().filter(c -> c.getHost().equals(host)).findFirst().orElseThrow();
    }

    @Test
    void 열린_alert만_host별로_집계하고_severity를_센다() {
        seed("A", "h1", "CRITICAL", AlertStatus.OPEN, 100L);
        seed("A", "h1", "HIGH", AlertStatus.OPEN, 110L);
        seed("A", "h2", "HIGH", AlertStatus.OPEN, 200L);

        List<HostAlertCount> counts = alerts.openAlertCountsByHost("A", AlertStatus.OPEN);
        assertEquals(2, counts.size());

        HostAlertCount h1 = find(counts, "h1");
        assertEquals(2L, h1.getOpenTotal());
        assertEquals(1L, h1.getOpenCritical());
        assertEquals(1L, h1.getOpenHigh());

        HostAlertCount h2 = find(counts, "h2");
        assertEquals(1L, h2.getOpenTotal());
        assertEquals(0L, h2.getOpenCritical());
        assertEquals(1L, h2.getOpenHigh());
    }

    @Test
    void 트리아지된_alert는_집계에서_빠진다() {
        seed("A", "h1", "CRITICAL", AlertStatus.CONFIRMED, 100L);
        seed("A", "h1", "HIGH", AlertStatus.OPEN, 110L);

        HostAlertCount h1 = find(alerts.openAlertCountsByHost("A", AlertStatus.OPEN), "h1");
        assertEquals(1L, h1.getOpenTotal());
        assertEquals(0L, h1.getOpenCritical());
        assertEquals(1L, h1.getOpenHigh());
    }

    @Test
    void 집계도_tenant_격리() {
        seed("A", "h1", "HIGH", AlertStatus.OPEN, 100L);
        seed("B", "h1", "CRITICAL", AlertStatus.OPEN, 200L);

        List<HostAlertCount> a = alerts.openAlertCountsByHost("A", AlertStatus.OPEN);
        assertEquals(1, a.size());
        assertEquals(0L, find(a, "h1").getOpenCritical());
    }

    // --- timeseries(버킷×severity 집계) ---

    private static final long HOUR = 3_600_000L;

    private static TimeBucketSeverityCount find(List<TimeBucketSeverityCount> rows, long bucketStart, String severity) {
        return rows.stream()
                .filter(r -> r.getBucketStart() == bucketStart && severity.equals(r.getSeverity()))
                .findFirst().orElseThrow();
    }

    @Test
    void timeseries_는_버킷과_severity로_묶어_카운트한다() {
        seed("A", "h1", "CRITICAL", AlertStatus.OPEN, 100L);
        seed("A", "h1", "HIGH", AlertStatus.OPEN, 200L);
        seed("A", "h1", "HIGH", AlertStatus.OPEN, HOUR + 50L);

        List<TimeBucketSeverityCount> rows = alerts.timeseries("A", 0L, 2 * HOUR, HOUR);

        assertEquals(1L, find(rows, 0L, "CRITICAL").getCnt());
        assertEquals(1L, find(rows, 0L, "HIGH").getCnt());
        assertEquals(1L, find(rows, HOUR, "HIGH").getCnt());
    }

    @Test
    void timeseries_도_tenant_격리와_시간범위_필터를_지킨다() {
        seed("A", "h1", "HIGH", AlertStatus.OPEN, 100L);
        seed("B", "h1", "CRITICAL", AlertStatus.OPEN, 100L);
        seed("A", "h1", "CRITICAL", AlertStatus.OPEN, 3 * HOUR);

        List<TimeBucketSeverityCount> rows = alerts.timeseries("A", 0L, 2 * HOUR, HOUR);

        assertEquals(1, rows.size());
        assertEquals(1L, find(rows, 0L, "HIGH").getCnt());
    }
}
