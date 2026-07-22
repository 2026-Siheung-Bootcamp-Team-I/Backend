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
}
