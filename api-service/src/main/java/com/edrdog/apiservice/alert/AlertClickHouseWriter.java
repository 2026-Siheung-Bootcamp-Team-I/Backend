package com.edrdog.apiservice.alert;

import com.edrdog.apiservice.alert.dto.Alert;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 판정기록(불변)을 ClickHouse HTTP(8123) 로 적재하고, 부팅 시 alerts 테이블 스키마를 보장한다.
 * archiver 의 ClickHouseWriter 와 같은 패턴이다(쿼리는 POST 본문 첫 줄, 데이터는 JSONEachRow 로 이어붙임).
 *
 * <p>테이블은 ReplacingMergeTree 라 같은 id 가 재삽입돼도 병합 시 한 행으로 접힌다.
 * 다만 병합은 비동기라 조회 쪽(AlertQueryBuilder)은 반드시 FINAL 로 dedup 한다.
 */
@Component
public class AlertClickHouseWriter {

    private static final Logger log = LoggerFactory.getLogger(AlertClickHouseWriter.class);

    private final RestClient client;
    private final ObjectMapper mapper;
    private final String table;
    private volatile boolean schemaReady = false;

    public AlertClickHouseWriter(
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

    /**
     * 부팅 시 alerts 테이블 생성 (개발용: 매 기동마다 IF NOT EXISTS).
     * CH 가 아직 없어도 앱은 떠야 하므로(수집·조회는 요청 시점에 다시 붙는다) 실패는 삼키고 경고만 남긴다.
     */
    @PostConstruct
    void ensureSchema() {
        try {
            execute("""
                    CREATE TABLE IF NOT EXISTS %s (
                        id String,
                        tenant_id String,
                        host String,
                        rule_id String,
                        mitre String,
                        severity String,
                        action String,
                        ts UInt64,
                        matched Array(String),
                        created_at DateTime64(3) DEFAULT now64(3)
                    ) ENGINE = ReplacingMergeTree(created_at)
                    ORDER BY (tenant_id, host, id)
                    """.formatted(table));
            schemaReady = true;
            log.info("ClickHouse alerts 스키마 준비 완료: {}", table);
        } catch (Exception e) {
            log.warn("ClickHouse alerts 스키마 준비 실패. ClickHouse 상태를 확인하세요. 앱은 계속 뜹니다.", e);
        }
    }

    /**
     * 판정기록 한 건을 alerts 테이블에 적재한다. id 는 결정적(AlertId)이라 재소비돼도 병합 시 한 행만 남는다.
     * created_at 은 CH 기본값(now64)에 맡겨 재삽입 시 최신본이 이기게 한다.
     */
    public void insert(String id, Alert alert) {
        if (!schemaReady) {
            // CH 가 부팅 시점에 죽어있었으면 테이블이 아직 없다. 첫 적재 때 한 번 더 시도해 자가복구한다.
            ensureSchema();
        }
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("id", id);
        row.put("tenant_id", nz(alert.tenantId()));
        row.put("host", nz(alert.host()));
        row.put("rule_id", nz(alert.ruleId()));
        row.put("mitre", nz(alert.mitre()));
        row.put("severity", nz(alert.severity()));
        row.put("action", nz(alert.action()));
        row.put("ts", alert.ts());
        row.put("matched", alert.matched() == null ? new ArrayList<>() : alert.matched());
        execute("INSERT INTO " + table + " FORMAT JSONEachRow\n" + toJson(row));
    }

    private String toJson(Map<String, Object> row) {
        try {
            return mapper.writeValueAsString(row);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("alert JSON 직렬화 실패: " + row, e);
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
