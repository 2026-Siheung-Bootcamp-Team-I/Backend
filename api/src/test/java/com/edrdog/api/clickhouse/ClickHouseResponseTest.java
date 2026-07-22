package com.edrdog.api.clickhouse;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ClickHouse FORMAT JSON 응답에서 data 배열만 뽑아내는 순수 파싱 검증.
 */
class ClickHouseResponseTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void data_배열을_행_리스트로_파싱() {
        String json = """
                {"meta":[{"name":"host","type":"String"}],
                 "data":[{"host":"h1","type":"process"},{"host":"h2","type":"network"}],
                 "rows":2}
                """;
        List<Map<String, Object>> rows = ClickHouseResponse.data(json, mapper);
        assertEquals(2, rows.size());
        assertEquals("h1", rows.get(0).get("host"));
        assertEquals("network", rows.get(1).get("type"));
    }

    @Test
    void data_가_비면_빈_리스트() {
        String json = """
                {"meta":[],"data":[],"rows":0}
                """;
        assertTrue(ClickHouseResponse.data(json, mapper).isEmpty());
    }
}
