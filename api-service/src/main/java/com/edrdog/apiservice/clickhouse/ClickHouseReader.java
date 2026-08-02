package com.edrdog.apiservice.clickhouse;

import com.edrdog.apiservice.query.ClickHouseQuery;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

/** ClickHouse 읽기 전용 조회. 응답은 FORMAT JSON 으로 받아 data 만 파싱한다. */
// 필터값은 SQL 본문이 아니라 ClickHouseHttp 가 URL 의 param_* 로 실어 보낸다. 본문에 이어붙이면 SQL 인젝션이 열린다.
@Component
public class ClickHouseReader {

    private final ClickHouseHttp http;
    private final ObjectMapper mapper;

    public ClickHouseReader(ClickHouseHttp http, ObjectMapper mapper) {
        this.http = http;
        this.mapper = mapper;
    }

    public List<Map<String, Object>> query(ClickHouseQuery q) {
        String response = http.query(q.sql() + " FORMAT JSON", q.params());
        return ClickHouseResponse.data(response, mapper);
    }
}
