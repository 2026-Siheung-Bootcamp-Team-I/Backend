package com.edrdog.archiver.clickhouse;

import com.edrdog.archiver.dto.Event;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Event 를 ClickHouse JSONEachRow 한 줄(JSON object)로 변환하는 순수 매핑.
 * 컬럼 순서를 events 테이블 정의와 맞추고, null String 필드는 ""(빈 문자열)로 치환한다.
 * (ClickHouse 는 input_format_null_as_default 기본 on 이라 null 도 흡수하지만, 그 설정과
 *  무관하게 non-Nullable String 컬럼에 항상 결정적으로 "" 가 들어가도록 명시적으로 치환한다.)
 */
public final class EventRow {

    private EventRow() {
    }

    public static String toJson(Event e, ObjectMapper mapper) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("host", nz(e.host()));
        row.put("type", nz(e.type()));
        row.put("ts", e.ts());
        row.put("process", nz(e.process()));
        row.put("parent", nz(e.parent()));
        row.put("cmdline", nz(e.cmdline()));
        row.put("dest_ip", nz(e.destIp()));
        row.put("dest_port", e.destPort());
        try {
            return mapper.writeValueAsString(row);
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("Event JSON 직렬화 실패: " + e, ex);
        }
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
