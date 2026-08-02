package com.edrdog.apiservice.clickhouse;

import com.edrdog.apiservice.query.ClickHouseQuery;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Map;

/** ClickHouse HTTP(8123) 읽기 전용 조회. 응답은 FORMAT JSON 으로 받아 data 만 파싱한다. */
// 필터값은 SQL 본문이 아니라 URL 의 param_* 로 나간다. 본문에 이어붙이면 SQL 인젝션이 열린다.
@Component
public class ClickHouseReader {

    private final RestClient client;
    private final ObjectMapper mapper;

    public ClickHouseReader(
            @Value("${edrdog.clickhouse.url}") String url,
            @Value("${edrdog.clickhouse.database}") String database,
            @Value("${edrdog.clickhouse.user}") String user,
            @Value("${edrdog.clickhouse.password}") String password,
            ObjectMapper mapper) {
        this.mapper = mapper;
        this.client = RestClient.builder()
                .baseUrl(url)
                .defaultHeader("X-ClickHouse-User", user)
                .defaultHeader("X-ClickHouse-Key", password)
                .defaultHeader("X-ClickHouse-Database", database)
                .build();
    }

    public List<Map<String, Object>> query(ClickHouseQuery q) {
        String body = q.sql() + " FORMAT JSON";
        String response = client.post()
                .uri(uriBuilder -> {
                    uriBuilder.path("/");
                    q.params().forEach((k, v) -> uriBuilder.queryParam("param_" + k, v));
                    return uriBuilder.build();
                })
                .contentType(MediaType.TEXT_PLAIN)
                .body(body)
                .retrieve()
                .body(String.class);
        return ClickHouseResponse.data(response, mapper);
    }
}
