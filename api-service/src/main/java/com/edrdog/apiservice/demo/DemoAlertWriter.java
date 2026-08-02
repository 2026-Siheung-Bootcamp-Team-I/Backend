package com.edrdog.apiservice.demo;

import com.edrdog.apiservice.alert.AlertId;
import com.edrdog.apiservice.alert.dto.Alert;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * 데모 시드 alerts 를 ClickHouse 에 직접 적재한다(DemoEventWriter 와 같은 패턴).
 * 평소 적재는 archiver 담당이고 여기는 발표용 과거 데이터 전용이라, 시드 플래그가 켜진 경우에만 빈으로 올라온다.
 * 테이블 스키마도 archiver 가 보장하므로 여기서는 INSERT 만 한다.
 *
 * <p>id 는 적재 경로와 같은 {@link AlertId} 로 계산한다. 결정적이라 재기동으로 다시 넣어도
 * ReplacingMergeTree 가 병합 시 한 행으로 접는다(트리아지한 status 오버레이도 그대로 붙는다).
 */
@Component
@ConditionalOnProperty(name = "edrdog.demo.seed", havingValue = "true")
public class DemoAlertWriter {

    private final RestClient client;
    private final ObjectMapper mapper;
    private final String table;

    public DemoAlertWriter(
            @Value("${edrdog.clickhouse.url}") String url,
            @Value("${edrdog.clickhouse.database}") String database,
            @Value("${edrdog.clickhouse.user}") String user,
            @Value("${edrdog.clickhouse.password}") String password,
            @Value("${edrdog.clickhouse.alerts-table}") String table,
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

    public void insert(List<Alert> alerts) {
        if (alerts.isEmpty()) {
            return;
        }
        execute("INSERT INTO " + table + " FORMAT JSONEachRow\n"
                + alerts.stream().map(this::toJson).collect(Collectors.joining("\n")));
    }

    /** created_at 은 ClickHouse 기본값(now64)에 맡겨 재삽입 시 최신본이 이기게 한다. */
    private String toJson(Alert alert) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("id", AlertId.of(alert.tenantId(), alert.host(), alert.ruleId(), alert.ts()));
        row.put("tenant_id", nz(alert.tenantId()));
        row.put("host", nz(alert.host()));
        row.put("rule_id", nz(alert.ruleId()));
        row.put("mitre", nz(alert.mitre()));
        row.put("severity", nz(alert.severity()));
        row.put("action", nz(alert.action()));
        row.put("ts", alert.ts());
        row.put("matched", alert.matched() == null ? new ArrayList<>() : alert.matched());
        row.put("domain", nz(alert.domain()));
        row.put("dest_ip", nz(alert.destIp()));
        try {
            return mapper.writeValueAsString(row);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("데모 alert 직렬화 실패: " + row, e);
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

    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
