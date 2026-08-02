package com.edrdog.apiservice.host;

import java.util.Map;

/**
 * 호스트 하나의 열린 alert severity 분포. 위험 점수(RiskScore)의 재료다.
 * 행 해석(fromRow)을 여기 말고 또 두면 엔드포인트 목록과 토폴로지의 점수가 갈린다.
 */
public record HostRisk(String host, long critical, long high, long medium, long low) {

    public static HostRisk fromRow(Map<String, Object> row) {
        return new HostRisk(str(row, "host"), num(row, "critical"), num(row, "high"),
                num(row, "medium"), num(row, "low"));
    }

    public long total() {
        return critical + high + medium + low;
    }

    public int score() {
        return RiskScore.of(critical, high, medium, low);
    }

    private static String str(Map<String, Object> row, String key) {
        Object v = row.get(key);
        return v == null ? "" : String.valueOf(v);
    }

    /** UInt64 는 ClickHouse JSON 에서 문자열로 오므로 숫자/문자열을 모두 받는다. */
    private static long num(Map<String, Object> row, String key) {
        Object v = row.get(key);
        if (v == null) {
            return 0L;
        }
        if (v instanceof Number n) {
            return n.longValue();
        }
        return Long.parseLong(String.valueOf(v));
    }
}
