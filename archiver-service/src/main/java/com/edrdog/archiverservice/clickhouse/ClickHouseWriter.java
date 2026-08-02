package com.edrdog.archiverservice.clickhouse;

import com.edrdog.archiverservice.dto.Event;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.List;

/**
 * ClickHouse HTTP(8123) 로 events 를 적재하고, 부팅 시 테이블 스키마를 보장한다.
 * 쿼리는 POST 본문 첫 줄에, 데이터(JSONEachRow)는 그 다음 줄부터 실어 URL 인코딩을 피한다.
 */
@Component
public class ClickHouseWriter {

    private static final Logger log = LoggerFactory.getLogger(ClickHouseWriter.class);

    private final RestClient client;
    private final ObjectMapper mapper;
    private final String table;

    public ClickHouseWriter(
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

    /** 나중에 추가돼 ALTER 로 한 번 더 보장하는 컬럼. */
    private static final List<String> ADDED_COLUMNS = List.of(
            "domain String",
            "detail String",
            "sha256 String"
    );

    /** 보관기간 7일. SHOW CREATE 결과와 문자열 비교하므로 정규형으로 쓴다. */
    private static final String TTL = "toDateTime(ingested_at) + toIntervalDay(7)";

    /** 부팅 시 events 테이블 생성 (개발용: 매 기동마다 IF NOT EXISTS). */
    @PostConstruct
    void ensureSchema() {
        execute("""
                CREATE TABLE IF NOT EXISTS %s (
                    host String,
                    tenant_id String,
                    type LowCardinality(String),
                    ts UInt64,
                    process String,
                    parent String,
                    cmdline String,
                    dest_ip String,
                    dest_port UInt16,
                    domain String,
                    detail String,
                    sha256 String,
                    ingested_at DateTime64(3) DEFAULT now64(3)
                ) ENGINE = MergeTree
                ORDER BY (tenant_id, host, ts)
                TTL %s
                """.formatted(table, TTL));

        // 기존 테이블에는 위 DDL 이 새 컬럼을 못 붙인다. 나중에 늘어난 컬럼은 ALTER 로 보장한다.
        for (String column : ADDED_COLUMNS) {
            execute("ALTER TABLE " + table + " ADD COLUMN IF NOT EXISTS " + column);
        }
        ensureTtl();
        log.info("ClickHouse 스키마 준비 완료: {}", table);
    }

    // 매번 걸면 전 파트 재계산 mutation 이 돌아 없을 때만 건다.
    private void ensureTtl() {
        if (query("SHOW CREATE TABLE " + table).contains(TTL)) {
            return;
        }
        execute("ALTER TABLE " + table + " MODIFY TTL " + TTL);
        log.info("ClickHouse TTL 적용: {} TTL {}", table, TTL);
    }

    // 건별 INSERT 는 파트가 건수만큼 쌓여 Too many parts 로 적재가 끊긴다.
    public void insert(List<Event> events) {
        if (events.isEmpty()) {
            return;
        }
        String body = "INSERT INTO " + table + " FORMAT JSONEachRow\n"
                + EventRow.toJsonRows(events, mapper);
        execute(body);
    }

    private void execute(String sql) {
        client.post()
                .uri("/")
                .contentType(MediaType.TEXT_PLAIN)
                .body(sql)
                .retrieve()
                .toBodilessEntity();
    }

    private String query(String sql) {
        String body = client.post()
                .uri("/")
                .contentType(MediaType.TEXT_PLAIN)
                .body(sql)
                .retrieve()
                .body(String.class);
        return body == null ? "" : body;
    }
}
