package com.edrdog.apiservice.alert;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 트리아지 status 오버레이 저장소 슬라이스(H2). tenant 조회 + id 일괄 조회 + upsert(같은 id 재저장) 확인.
 */
@DataJpaTest
class AlertStatusRepositoryTest {

    @Autowired
    private AlertStatusRepository statuses;

    private void save(String id, String tenantId, String status) {
        statuses.save(AlertStatusRecord.of(id, tenantId, status, Instant.now()));
    }

    @Test
    void findByTenantId_는_tenant_격리() {
        save("a1", "A", AlertStatus.CONFIRMED);
        save("a2", "A", AlertStatus.FALSE_POSITIVE);
        save("b1", "B", AlertStatus.CONFIRMED);

        List<AlertStatusRecord> a = statuses.findByTenantId("A");
        assertEquals(2, a.size());
        assertEquals(1, statuses.findByTenantId("B").size());
    }

    @Test
    void findAllById_는_주어진_id들의_status만() {
        save("a1", "A", AlertStatus.CONFIRMED);
        save("a2", "A", AlertStatus.FALSE_POSITIVE);

        List<AlertStatusRecord> found = statuses.findAllById(List.of("a1", "nope"));
        assertEquals(1, found.size());
        assertEquals(AlertStatus.CONFIRMED, found.get(0).getStatus());
    }

    @Test
    void 같은_id_재저장은_status를_덮어쓴다() {
        save("a1", "A", AlertStatus.CONFIRMED);
        save("a1", "A", AlertStatus.FALSE_POSITIVE);

        assertEquals(1, statuses.count());
        assertEquals(AlertStatus.FALSE_POSITIVE, statuses.findById("a1").orElseThrow().getStatus());
    }
}
