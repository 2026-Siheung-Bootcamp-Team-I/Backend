package com.edrdog.apiservice.intelligence.topology;

import java.util.Map;

/**
 * ClickHouse 행(Map) 읽기 도우미. UInt64 는 JSON 에서 문자열로 오므로 숫자/문자열을 모두 받는다
 * (EventResponse.asLong 과 같은 이유).
 */
final class Rows {

    private Rows() {
    }

    static String str(Map<String, Object> row, String key) {
        Object v = row.get(key);
        return v == null ? "" : String.valueOf(v);
    }

    static long num(Map<String, Object> row, String key) {
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
