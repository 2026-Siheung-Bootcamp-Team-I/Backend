package com.edrdog.apiservice.demo;

import com.edrdog.apiservice.alert.AlertId;
import com.edrdog.apiservice.alert.dto.Alert;
import com.edrdog.apiservice.clickhouse.ClickHouseHttp;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * 데모 시드 alerts 를 archiver 를 거치지 않고 ClickHouse 에 직접 적재한다(테이블 스키마는 archiver 가 보장하는 걸 쓴다).
 * 조건부 빈을 풀면 운영 판정기록에 데모 alert 가 섞인다({@code edrdog.demo.seed} 가 그걸 막는 유일한 장치다).
 *
 * <p>id 는 적재 경로와 같은 {@link AlertId} 로 계산한다. 임의 id 로 바꾸면 재기동마다 같은 alert 가
 * 새 행으로 쌓인다(결정적이라야 ReplacingMergeTree 가 한 행으로 접는다).
 */
@Component
@ConditionalOnProperty(name = "edrdog.demo.seed", havingValue = "true")
public class DemoAlertWriter {

    private final ClickHouseHttp http;
    private final ObjectMapper mapper;
    private final String table;

    public DemoAlertWriter(
            ClickHouseHttp http,
            @Value("${edrdog.clickhouse.alerts-table}") String table,
            ObjectMapper mapper) {
        this.http = http;
        this.table = table;
        this.mapper = mapper;
    }

    public void insert(List<Alert> alerts) {
        if (alerts.isEmpty()) {
            return;
        }
        http.execute("INSERT INTO " + table + " FORMAT JSONEachRow\n"
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

    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
