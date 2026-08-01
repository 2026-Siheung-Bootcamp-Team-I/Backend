package com.edrdog.apiservice.search.web;

import com.edrdog.apiservice.alert.ThreatCatalog;

import java.util.Map;

/**
 * 검색 결과의 알림 한 줄. 화면은 id 로 GET /api/alerts/{id} 에 바로 넘어간다.
 * threatName 은 화면에 보이는 한글 위협명이고, 이 이름으로 검색해도 걸린다(SearchService.threatRuleIds).
 */
public record AlertHit(
        String id,
        String host,
        String ruleId,
        String threatName,
        String mitre,
        String severity,
        long ts
) {
    public static AlertHit fromRow(Map<String, Object> row) {
        String ruleId = str(row, "rule_id");
        return new AlertHit(str(row, "id"), str(row, "host"), ruleId, ThreatCatalog.threatName(ruleId),
                str(row, "mitre"), str(row, "severity"), asLong(row, "ts"));
    }

    private static String str(Map<String, Object> row, String key) {
        Object v = row.get(key);
        return v == null ? "" : String.valueOf(v);
    }

    /** ClickHouse UInt64 는 JSON 에서 문자열로 온다(AlertResponse.asLong 과 같은 이유). */
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
}
