package com.edrdog.archiverservice.clickhouse;

import com.edrdog.archiverservice.dto.Event;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Event 를 ClickHouse JSONEachRow 한 줄(JSON object)로 변환하는 순수 매핑.
 * 컬럼 순서를 events 테이블 정의와 맞추고, null String 필드는 ""(빈 문자열)로 치환한다
 * (ClickHouse 의 input_format_null_as_default 설정과 무관하게 항상 결정적으로 치환하기 위함).
 */
public final class EventRow {

    private EventRow() {
    }

    public static String toJson(Event e, ObjectMapper mapper) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("host", nz(e.host()));
        row.put("tenant_id", nz(e.tenantId()));
        row.put("type", nz(e.type()));
        row.put("ts", e.ts());
        row.put("process", nz(e.process()));
        row.put("parent", nz(e.parent()));
        row.put("cmdline", nz(e.cmdline()));
        row.put("dest_ip", nz(e.destIp()));
        row.put("dest_port", e.destPort());
        row.put("domain", nz(e.domain()));
        row.put("detail", nz(e.detail()));
        row.put("sha256", nz(e.sha256()));
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
