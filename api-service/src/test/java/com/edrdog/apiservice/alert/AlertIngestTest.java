package com.edrdog.apiservice.alert;

import com.edrdog.apiservice.alert.dto.Alert;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.data.domain.PageRequest;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 적재 멱등성(H2). 같은 alert 를 두 번 소비해도 한 행만 남고,
 * 이미 트리아지된(confirmed) alert 는 재소비돼도 open 으로 되돌아가지 않는다.
 */
@DataJpaTest
class AlertIngestTest {

    @Autowired
    private AlertRepository alerts;

    private AlertService service() {
        return new AlertService(alerts);
    }

    private static Alert alert(String tenantId, long ts) {
        return new Alert("h1", "RULE_A", "T1059", "HIGH", "notify", ts, List.of("m1"), tenantId);
    }

    @Test
    void 같은_alert_두번_ingest_하면_한행() {
        AlertService svc = service();
        svc.ingest(alert("A", 100L));
        svc.ingest(alert("A", 100L));

        assertEquals(1, alerts.search("A", null, null, null, null, null, PageRequest.of(0, 10)).size());
    }

    @Test
    void 이미_confirmed_면_재소비해도_open_으로_안돌아간다() {
        AlertService svc = service();
        svc.ingest(alert("A", 100L));
        String id = AlertId.of("A", "h1", "RULE_A", 100L);
        svc.triage("A", id, AlertStatus.CONFIRMED);

        svc.ingest(alert("A", 100L));

        assertEquals(AlertStatus.CONFIRMED, alerts.findById(id).orElseThrow().getStatus());
    }

    @Test
    void tenantId_없으면_skip() {
        AlertService svc = service();
        svc.ingest(alert(null, 100L));
        svc.ingest(alert("  ", 100L));

        assertEquals(0, alerts.count());
    }
}
