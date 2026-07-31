package com.edrdog.apiservice.alert.web;

import java.util.Map;

/**
 * 판정을 유발한 원본 이벤트(alert 상세 전용). events(ClickHouse) 한 행을 그대로 옮긴 것이라
 * 화면에서 "어떤 프로세스가 무엇을 했는지" 를 판정 근거 요약(matched) 없이도 확인할 수 있다.
 * 목록 응답에는 담지 않는다(행마다 events 를 조회하면 느리다).
 *
 * @param matchedBy 이 이벤트를 무엇으로 특정했는지. {@code summary} 가 {@code rule_type} 보다 확신이 강하다.
 *                  {@code rule_type} 은 이벤트 종류만 맞춘 것이라 같은 종류가 여럿이면 시각으로 갈렸다.
 *                  화면은 그 경우 확신이 낮다는 것을 사용자에게 알려야 한다.
 */
public record SourceEvent(
        String host,
        String type,
        long ts,
        String process,
        String parent,
        String cmdline,
        String destIp,
        int destPort,
        String domain,
        String detail,
        String sha256,
        String matchedBy
) {
    /** 판정 근거 요약(matched)이 짚은 이벤트. type 에 더해 프로세스명·부모·경로까지 일치한다. */
    public static final String BY_SUMMARY = "summary";
    /** 룰이 걸리는 이벤트 type 만 일치. 같은 type 이 여럿이면 시각으로 갈렸다. */
    public static final String BY_RULE_TYPE = "rule_type";

    public static SourceEvent fromRow(Map<String, Object> row, String matchedBy) {
        return new SourceEvent(
                str(row, "host"),
                str(row, "type"),
                asLong(row, "ts"),
                str(row, "process"),
                str(row, "parent"),
                str(row, "cmdline"),
                str(row, "dest_ip"),
                (int) asLong(row, "dest_port"),
                str(row, "domain"),
                str(row, "detail"),
                str(row, "sha256"),
                matchedBy);
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
}
