package com.edrdog.archiver.clickhouse;

import com.edrdog.archiver.dto.Alert;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Alert 를 ClickHouse JSONEachRow 한 줄(JSON object)로 변환하는 순수 매핑.
 * 컬럼 순서를 detections 테이블 정의와 맞추고, null String 필드는 ""(빈 문자열)로 치환한다.
 * ingested_at 은 테이블 DEFAULT 로 채워지므로 여기서는 넣지 않는다.
 */
public final class DetectionRow {

    private DetectionRow() {
    }

    public static String toJson(Alert a, ObjectMapper mapper) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("host", nz(a.host()));
        row.put("rule_id", nz(a.ruleId()));
        row.put("mitre", nz(a.mitre()));
        row.put("severity", nz(a.severity()));
        row.put("action", nz(a.action()));
        row.put("ts", a.ts());
        row.put("dest_ip", nz(a.destIp()));
        row.put("dest_port", a.destPort());
        try {
            return mapper.writeValueAsString(row);
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("Alert JSON 직렬화 실패: " + a, ex);
        }
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
