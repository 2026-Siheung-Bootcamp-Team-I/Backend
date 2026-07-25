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
                    ingested_at DateTime64(3) DEFAULT now64(3)
                ) ENGINE = MergeTree
                ORDER BY (tenant_id, host, ts)
                """.formatted(table));
        log.info("ClickHouse 스키마 준비 완료: {}", table);
    }

    /** 이벤트 한 건을 events 테이블에 적재. */
    public void insert(Event event) {
        String body = "INSERT INTO " + table + " FORMAT JSONEachRow\n"
                + EventRow.toJson(event, mapper);
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
}
