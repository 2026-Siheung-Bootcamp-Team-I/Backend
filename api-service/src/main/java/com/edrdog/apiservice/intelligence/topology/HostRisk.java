package com.edrdog.apiservice.intelligence.topology;

import java.util.Map;

/** 호스트 하나의 열린 alert severity 분포. 위험 점수(RiskScore)의 재료다. */
public record HostRisk(String host, long critical, long high, long medium, long low) {

    public static HostRisk fromRow(Map<String, Object> row) {
        return new HostRisk(Rows.str(row, "host"), Rows.num(row, "critical"), Rows.num(row, "high"),
                Rows.num(row, "medium"), Rows.num(row, "low"));
    }

    public long total() {
        return critical + high + medium + low;
    }

    public int score() {
        return RiskScore.of(critical, high, medium, low);
    }
}
