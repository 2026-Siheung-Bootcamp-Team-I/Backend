package com.edrdog.archiverservice.alert;

import com.edrdog.archiverservice.alert.dto.Alert;
import com.edrdog.archiverservice.clickhouse.ClickHouseHttp;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 판정기록(불변)을 ClickHouse 에 적재하고, 부팅 시 alerts 테이블 스키마를 보장한다.
 * ReplacingMergeTree 병합은 비동기라 조회 쪽(api-service AlertQueryBuilder)은 반드시 FINAL 로 dedup 한다.
 */
@Component
public class AlertClickHouseWriter {

    private static final Logger log = LoggerFactory.getLogger(AlertClickHouseWriter.class);

    private final ClickHouseHttp http;
    private final ObjectMapper mapper;
    private final String table;
    private volatile boolean schemaReady = false;

    /** 나중에 추가돼 ALTER 로 한 번 더 보장하는 컬럼. */
    private static final List<String> ADDED_COLUMNS = List.of(
            "domain String",
            "dest_ip String"
    );

    /** 보관기간 90일. SHOW CREATE 결과와 문자열 비교하므로 정규형으로 쓴다. */
    private static final String TTL = "toDateTime(created_at) + toIntervalDay(90)";

    public AlertClickHouseWriter(
            ClickHouseHttp http,
            @Value("${edrdog.clickhouse.alerts-table}") String table,
            ObjectMapper mapper) {
        this.http = http;
        this.table = table;
        this.mapper = mapper;
    }

    /** 부팅 시 alerts 테이블 생성. CH 가 없어도 앱은 떠야 하므로 실패는 경고만 남긴다. */
    @PostConstruct
    void ensureSchema() {
        try {
            http.execute("""
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
                        domain String,
                        dest_ip String,
                        created_at DateTime64(3) DEFAULT now64(3)
                    ) ENGINE = ReplacingMergeTree(created_at)
                    ORDER BY (tenant_id, host, id)
                    TTL %s
                    """.formatted(table, TTL));

            // 기존 테이블에는 위 DDL 이 새 컬럼을 못 붙인다. 나중에 늘어난 컬럼은 ALTER 로 보장한다.
            for (String column : ADDED_COLUMNS) {
                http.execute("ALTER TABLE " + table + " ADD COLUMN IF NOT EXISTS " + column);
            }
            ensureTtl();
            schemaReady = true;
            log.info("ClickHouse alerts 스키마 준비 완료: {}", table);
        } catch (Exception e) {
            log.warn("ClickHouse alerts 스키마 준비 실패. ClickHouse 상태를 확인하세요. 앱은 계속 뜹니다.", e);
        }
    }

    // 매번 걸면 전 파트 재계산 mutation 이 돌아 없을 때만 건다.
    private void ensureTtl() {
        if (http.query("SHOW CREATE TABLE " + table).contains(TTL)) {
            return;
        }
        http.execute("ALTER TABLE " + table + " MODIFY TTL " + TTL);
        log.info("ClickHouse TTL 적용: {} TTL {}", table, TTL);
    }

    /** 판정 한 건을 적재한다. created_at 은 CH 기본값(now64)에 맡겨 재삽입 시 최신본이 이기게 한다. */
    public void insert(String id, Alert alert) {
        if (!schemaReady) {
            // 부팅 때 CH 가 죽어 있었으면 테이블이 없다. 첫 적재에서 한 번 더 시도한다.
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
        row.put("domain", nz(alert.domain()));
        row.put("dest_ip", nz(alert.destIp()));
        http.execute("INSERT INTO " + table + " FORMAT JSONEachRow\n" + toJson(row));
    }

    private String toJson(Map<String, Object> row) {
        try {
            return mapper.writeValueAsString(row);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("alert JSON 직렬화 실패: " + row, e);
        }
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
