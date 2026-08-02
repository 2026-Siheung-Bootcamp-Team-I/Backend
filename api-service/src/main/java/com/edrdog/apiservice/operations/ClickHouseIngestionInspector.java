package com.edrdog.apiservice.operations;

import com.edrdog.apiservice.clickhouse.ClickHouseReader;
import com.edrdog.apiservice.query.ClickHouseQuery;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

/**
 * ClickHouse 테이블(archiver 가 적재하는 events/alerts)의 최근 적재 지연(초)과 최근 5분 적재 건수를 구한다.
 * 조회는 ClickHouseReader 를 그대로 재사용한다.
 *
 * <p>지연은 ClickHouse 서버 시계(now64)로 계산해 API 서버와 ClickHouse 간 시계 오차에 흔들리지 않게 한다.
 */
@Component
public class ClickHouseIngestionInspector {

    private static final String RECENT_WINDOW = "5 MINUTE";

    private final ClickHouseReader reader;

    public ClickHouseIngestionInspector(ClickHouseReader reader) {
        this.reader = reader;
    }

    public ClickHouseIngestionResult check(String table, String timestampColumn) {
        try {
            String sql = "SELECT count() AS totalCount, "
                    + "dateDiff('second', max(" + timestampColumn + "), now64(3)) AS lagSeconds, "
                    + "countIf(" + timestampColumn + " >= now64(3) - INTERVAL " + RECENT_WINDOW + ") AS recentCount "
                    + "FROM " + table;
            List<Map<String, Object>> rows = reader.query(new ClickHouseQuery(sql, Map.of()));
            if (rows.isEmpty()) {
                return ClickHouseIngestionResult.of(table, null, 0);
            }
            Map<String, Object> row = rows.get(0);
            long totalCount = asLong(row.get("totalCount"));
            // 빈 테이블의 max() 는 NULL 이 아니라 1970 이라, 그대로 믿으면 "엄청나게 오래됨" 으로 읽힌다.
            Long lagSeconds = totalCount == 0 ? null : asLong(row.get("lagSeconds"));
            long recentCount = asLong(row.get("recentCount"));
            return ClickHouseIngestionResult.of(table, lagSeconds, recentCount);
        } catch (Exception e) {
            return ClickHouseIngestionResult.error(table, e.getMessage());
        }
    }

    private static long asLong(Object v) {
        return v == null ? 0L : Long.parseLong(String.valueOf(v));
    }
}
