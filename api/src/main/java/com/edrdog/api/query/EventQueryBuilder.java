package com.edrdog.api.query;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * events 조회/요약 SQL 을 만드는 순수 로직. 필터는 파라미터 바인딩으로만 넣고, limit 은 상한으로 클램프한다.
 */
@Component
public class EventQueryBuilder {

    static final int DEFAULT_LIMIT = 100;
    static final int MAX_LIMIT = 1000;

    private static final String COLUMNS =
            "host, type, ts, process, parent, cmdline, dest_ip, dest_port, ingested_at";

    private final String table;

    public EventQueryBuilder(@Value("${edrdog.clickhouse.table}") String table) {
        this.table = table;
    }

    /** host/type/from/to 필터(옵션)로 최신순 events 조회. limit 은 1..MAX 로 클램프. */
    public ChQuery events(String host, String type, Long from, Long to, Integer limit) {
        Map<String, String> params = new LinkedHashMap<>();
        String where = where(host, type, from, to, params);
        String sql = "SELECT " + COLUMNS + " FROM " + table
                + where
                + " ORDER BY ts DESC LIMIT " + clampLimit(limit);
        return new ChQuery(sql, params);
    }

    /** type 별 건수 집계. 시간범위 필터(옵션) 지원. */
    public ChQuery summaryByType(Long from, Long to) {
        Map<String, String> params = new LinkedHashMap<>();
        String where = where(null, null, from, to, params);
        String sql = "SELECT type, count() AS cnt FROM " + table
                + where
                + " GROUP BY type ORDER BY cnt DESC";
        return new ChQuery(sql, params);
    }

    private static String where(String host, String type, Long from, Long to, Map<String, String> params) {
        List<String> conds = new ArrayList<>();
        if (hasText(host)) {
            conds.add("host = {host:String}");
            params.put("host", host.trim());
        }
        if (hasText(type)) {
            conds.add("type = {type:String}");
            params.put("type", type.trim());
        }
        if (from != null) {
            conds.add("ts >= {from:UInt64}");
            params.put("from", String.valueOf(from));
        }
        if (to != null) {
            conds.add("ts <= {to:UInt64}");
            params.put("to", String.valueOf(to));
        }
        return conds.isEmpty() ? "" : " WHERE " + String.join(" AND ", conds);
    }

    private static int clampLimit(Integer limit) {
        if (limit == null || limit <= 0) {
            return DEFAULT_LIMIT;
        }
        return Math.min(limit, MAX_LIMIT);
    }

    private static boolean hasText(String s) {
        return s != null && !s.trim().isEmpty();
    }
}
