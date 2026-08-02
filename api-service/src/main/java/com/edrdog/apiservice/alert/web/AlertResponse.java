package com.edrdog.apiservice.alert.web;

import com.edrdog.apiservice.alert.ThreatCatalog;

import java.util.List;
import java.util.Map;

/**
 * alert 조회/상세/트리아지 응답. 목록과 상세가 같은 형태를 쓴다(matched 포함).
 * 판정기록은 ClickHouse 행(Map)으로 오고, status 는 오버레이(MySQL)에서 병합한 값을 넣는다.
 *
 * @param domain      이 알림과 관련된 목적지 도메인 (판정 근거 중 관측된 것, 없으면 빈 문자열)
 * @param destIp      이 알림과 관련된 목적지 IP (출처는 domain 과 같다)
 * @param sourceEvent 판정을 유발한 원본 이벤트 (목록이거나 못 찾았으면 null)
 * @param incidentId  이 알림이 속한 사건의 id (목록이거나 조회 기간 안에서 못 찾았으면 null)
 */
// sourceEvent/incidentId 를 목록에서도 채우면 행마다 events 조회와 사건 묶기가 돈다.
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
        List<String> matched,
        String domain,
        String destIp,
        SourceEvent sourceEvent,
        String incidentId
) {
    public static AlertResponse fromRow(Map<String, Object> row, String status) {
        return fromRow(row, status, null);
    }

    public static AlertResponse fromRow(Map<String, Object> row, String status, SourceEvent sourceEvent) {
        String ruleId = str(row, "rule_id");
        return new AlertResponse(str(row, "id"), str(row, "host"), ruleId, ThreatCatalog.threatName(ruleId),
                str(row, "mitre"), str(row, "severity"), str(row, "action"), asLong(row, "ts"), status,
                matched(row), str(row, "domain"), str(row, "dest_ip"), sourceEvent, null);
    }

    /** 사건 id 를 얹은 사본. */
    // 조립을 웹 계층으로 미루는 장치다. 서비스끼리 alert ↔ incident 로 맞물리면 순환이다.
    public AlertResponse withIncidentId(String incidentId) {
        return new AlertResponse(id, host, ruleId, threatName, mitre, severity, action, ts, status,
                matched, domain, destIp, sourceEvent, incidentId);
    }

    private static String str(Map<String, Object> row, String key) {
        Object v = row.get(key);
        return v == null ? "" : String.valueOf(v);
    }

    // ClickHouse UInt64 는 JSON 에서 문자열로 온다. Number 로만 받으면 ts 가 통째로 깨진다.
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
