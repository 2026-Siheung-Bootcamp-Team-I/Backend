package com.edrdog.apiservice.alert.web;

import com.edrdog.apiservice.alert.ThreatCatalog;

import java.util.List;
import java.util.Map;

/**
 * alert 조회/상세/트리아지 응답. 목록과 상세가 같은 형태를 쓴다(matched 포함).
 * threatName 은 ruleId 를 화면 표시용 한글로 옮긴 값이다(원문 ruleId/mitre 는 유지).
 * 판정기록은 ClickHouse 행(Map)으로 오고, status 는 오버레이(MySQL)에서 병합한 값을 넣는다.
 */
public record AlertResponse(
        String id,
        String host,
        String ruleId,
        String threatName,
        String mitre,
        String severity,
        String action,
        long ts,
        String status,
        List<String> matched
) {
    /** ClickHouse 판정기록 한 행 + 병합된 status 로 응답을 만든다. */
    public static AlertResponse fromRow(Map<String, Object> row, String status) {
        String ruleId = str(row, "rule_id");
        return new AlertResponse(str(row, "id"), str(row, "host"), ruleId, ThreatCatalog.threatName(ruleId),
                str(row, "mitre"), str(row, "severity"), str(row, "action"), asLong(row, "ts"), status,
                matched(row));
    }

    private static String str(Map<String, Object> row, String key) {
        Object v = row.get(key);
        return v == null ? "" : String.valueOf(v);
    }

    /** ClickHouse UInt64 는 JSON 에서 문자열로 오므로 문자열/숫자 모두 안전하게 파싱한다. */
    private static long asLong(Map<String, Object> row, String key) {
        Object v = row.get(key);
        if (v == null) {
            return 0L;
        }
        if (v instanceof Number n) {
            return n.longValue();
        }
        return Long.parseLong(String.valueOf(v));
    }

    @SuppressWarnings("unchecked")
    private static List<String> matched(Map<String, Object> row) {
        Object v = row.get("matched");
        if (v instanceof List<?> list) {
            return list.stream().map(String::valueOf).toList();
        }
        return List.of();
    }
}
