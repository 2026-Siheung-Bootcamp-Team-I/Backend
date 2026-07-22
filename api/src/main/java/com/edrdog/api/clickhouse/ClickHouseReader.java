package com.edrdog.api.clickhouse;

import com.edrdog.api.query.ChQuery;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Map;

/**
 * ClickHouse HTTP(8123) 읽기 전용 조회. SQL 은 POST 본문에, 필터값은 URL 의 param_* 로 실어
 * 파라미터 바인딩({name:Type})으로 안전하게 넣는다. 응답은 FORMAT JSON 으로 받아 data 만 파싱한다.
 */
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

    /** ChQuery(sql + 바인딩 파라미터)를 실행해 결과 행 목록을 돌려준다. */
    public List<Map<String, Object>> query(ChQuery q) {
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
        return ChResponse.data(response, mapper);
    }
}
