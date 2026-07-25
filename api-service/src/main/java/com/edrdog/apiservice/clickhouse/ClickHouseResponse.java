package com.edrdog.apiservice.clickhouse;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.List;
import java.util.Map;

/**
 * ClickHouse FORMAT JSON 응답 파싱(순수). 응답은 {"meta":[...],"data":[...],"rows":N} 형태이며
 * 여기서는 data 배열만 행(Map) 리스트로 뽑는다.
 */
public final class ClickHouseResponse {

    private ClickHouseResponse() {
    }

    public static List<Map<String, Object>> data(String json, ObjectMapper mapper) {
        try {
            JsonNode data = mapper.readTree(json).path("data");
            return mapper.convertValue(data, new TypeReference<List<Map<String, Object>>>() {
            });
        } catch (Exception e) {
            throw new IllegalStateException("ClickHouse 응답 파싱 실패: " + json, e);
        }
    }
}
