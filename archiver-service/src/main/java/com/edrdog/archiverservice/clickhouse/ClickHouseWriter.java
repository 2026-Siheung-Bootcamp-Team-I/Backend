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

    /** 나중에 추가된 컬럼. CREATE 문에도 있지만 ALTER 로 한 번 더 보장한다(아래 ensureSchema 주석 참고). */
    private static final List<String> ADDED_COLUMNS = List.of(
            "domain String",
            "detail String",
            "sha256 String"
    );

    /** 보관기간 7일. INTERVAL 7 DAY 가 아니라 정규형인 건 아래 SHOW CREATE 결과와 문자열 비교하기 때문. */
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

        // CREATE TABLE IF NOT EXISTS 는 이미 있는 테이블의 스키마를 바꾸지 않는다. 그래서 배포된 서버처럼
        // 예전 컬럼 구성으로 만들어진 테이블에는 위 DDL 로 새 컬럼이 붙지 않고, 그 컬럼을 담은 INSERT 가
        // 통째로 실패해 적재가 끊긴다. 나중에 늘어난 컬럼은 ALTER 로 한 번 더 보장한다.
        for (String column : ADDED_COLUMNS) {
            execute("ALTER TABLE " + table + " ADD COLUMN IF NOT EXISTS " + column);
        }
        ensureTtl();
        log.info("ClickHouse 스키마 준비 완료: {}", table);
    }

    /** TTL 도 위 컬럼과 같은 이유로 ALTER 가 필요하다. 매번 걸면 전 파트 재계산 mutation 이 돌아 없을 때만 건다. */
    private void ensureTtl() {
        if (query("SHOW CREATE TABLE " + table).contains(TTL)) {
            return;
        }
        execute("ALTER TABLE " + table + " MODIFY TTL " + TTL);
        log.info("ClickHouse TTL 적용: {} TTL {}", table, TTL);
    }

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
