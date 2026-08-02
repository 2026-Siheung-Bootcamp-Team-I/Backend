package com.edrdog.apiservice.demo;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.stream.Collectors;

/**
 * 데모 시드 events 를 archiver 를 거치지 않고 ClickHouse 에 직접 적재한다(테이블 스키마는 archiver 가 보장하는 걸 쓴다).
 * 조건부 빈을 풀면 운영 이벤트에 데모 데이터가 섞인다({@code edrdog.demo.seed} 가 그걸 막는 유일한 장치다).
 */
@Component
@ConditionalOnProperty(name = "edrdog.demo.seed", havingValue = "true")
public class DemoEventWriter {

    /** 한 요청에 싣는 행 수 상한. 안 쪼개면 수백 건이 한 요청 본문에 통째로 들어간다. */
    private static final int BATCH = 200;

    private final RestClient client;
    private final ObjectMapper mapper;
    private final String table;

    public DemoEventWriter(
            @Value("${edrdog.clickhouse.url}") String url,
            @Value("${edrdog.clickhouse.database}") String database,
            @Value("${edrdog.clickhouse.user}") String user,
            @Value("${edrdog.clickhouse.password}") String password,
            @Value("${edrdog.clickhouse.table}") String table,
            ObjectMapper mapper) {
        this.table = table;
        this.mapper = mapper;
        this.client = RestClient.builder()
                .baseUrl(url)
                .defaultHeader("X-ClickHouse-User", user)
                .defaultHeader("X-ClickHouse-Key", password)
                .defaultHeader("X-ClickHouse-Database", database)
                .build();
    }

    public void insert(List<DemoEvent> events) {
        for (int i = 0; i < events.size(); i += BATCH) {
            List<DemoEvent> batch = events.subList(i, Math.min(i + BATCH, events.size()));
            execute("INSERT INTO " + table + " FORMAT JSONEachRow\n" + toJsonLines(batch));
        }
    }

    private String toJsonLines(List<DemoEvent> events) {
        return events.stream().map(this::toJson).collect(Collectors.joining("\n"));
    }

    private String toJson(DemoEvent event) {
        try {
            return mapper.writeValueAsString(event);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("데모 이벤트 직렬화 실패: " + event, e);
        }
    }

    private void execute(String sql) {
        client.post()
                .uri("/")
                .contentType(MediaType.TEXT_PLAIN)
                .body(sql)
                .retrieve()
                .toBodilessEntity();
    }
}
