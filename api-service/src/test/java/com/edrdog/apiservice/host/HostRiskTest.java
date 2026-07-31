package com.edrdog.apiservice.host;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** 호스트 severity 분포 행 읽기와 점수 위임 검증. */
class HostRiskTest {

    @Test
    void severity_행은_문자열_숫자를_읽는다() {
        HostRisk risk = HostRisk.fromRow(
                Map.of("host", "h1", "critical", "1", "high", "2", "medium", "0", "low", "0"));

        assertEquals("h1", risk.host());
        assertEquals(1, risk.critical());
        assertEquals(2, risk.high());
        assertEquals(3, risk.total());
    }

    @Test
    void 빠진_칸은_0_으로_읽는다() {
        Map<String, Object> row = new HashMap<>();
        row.put("host", "h1");

        HostRisk risk = HostRisk.fromRow(row);

        assertEquals(0, risk.total());
        assertEquals(0, risk.score());
    }

    @Test
    void 점수는_RiskScore_를_그대로_쓴다() {
        HostRisk risk = new HostRisk("h1", 1, 2, 3, 4);

        assertEquals(RiskScore.of(1, 2, 3, 4), risk.score());
    }
}
