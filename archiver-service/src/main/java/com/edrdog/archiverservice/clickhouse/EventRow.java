package com.edrdog.archiverservice.clickhouse;

import com.edrdog.schema.Event;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Event 를 ClickHouse JSONEachRow 한 줄(JSON object)로 변환하는 순수 매핑.
 * 컬럼 순서를 events 테이블 정의와 맞춘다. proto3 는 관측 못 한 문자열을 빈 값으로 주므로
 * 예전 null 치환은 필요 없다(적재되는 값은 그때와 같은 "" 다).
 */
public final class EventRow {

    private EventRow() {
    }

    /** 여러 건을 JSONEachRow 본문 한 덩어리로 잇는다. */
    public static String toJsonRows(List<Event> events, ObjectMapper mapper) {
        return events.stream()
                .map(e -> toJson(e, mapper))
                .collect(Collectors.joining("\n"));
    }

    public static String toJson(Event e, ObjectMapper mapper) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("host", e.getHost());
        row.put("tenant_id", e.getTenantId());
        row.put("type", e.getType());
        row.put("ts", e.getTs());
        row.put("process", e.getProcess());
        row.put("parent", e.getParent());
        row.put("cmdline", e.getCmdline());
        row.put("dest_ip", e.getDestIp());
        row.put("dest_port", e.getDestPort());
        row.put("domain", e.getDomain());
        row.put("detail", e.getDetail());
        row.put("sha256", e.getSha256());
        try {
            return mapper.writeValueAsString(row);
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("Event JSON 직렬화 실패: " + e, ex);
        }
    }
}
