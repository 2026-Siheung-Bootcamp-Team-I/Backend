package com.edrdog.apiservice.search.web;

import com.edrdog.apiservice.web.EventId;

import java.util.Map;

/**
 * 검색 결과의 이벤트 한 줄. host 와 ts 는 화면 표시가 아니라 이동 때문에 싣는다.
 * 이벤트 단건 조회가 GET /api/events/{id}?host=&ts= 라서 셋이 다 있어야 그 이벤트로 넘어갈 수 있다.
 */
public record EventHit(
        String id,
        String host,
        long ts,
        String type,
        String process,
        String cmdline,
        String domain,
        String destIp,
        String sha256
) {
    public static EventHit fromRow(Map<String, Object> row) {
        String host = str(row, "host");
        return new EventHit(EventId.ofRow(host, row), host, asLong(row, "ts"), str(row, "type"),
                str(row, "process"), str(row, "cmdline"), str(row, "domain"), str(row, "dest_ip"),
                str(row, "sha256"));
    }

    private static String str(Map<String, Object> row, String key) {
        Object v = row.get(key);
        return v == null ? "" : String.valueOf(v);
    }

    /** ClickHouse UInt64 는 JSON 에서 문자열로 온다(EventResponse.asLong 과 같은 이유). */
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
