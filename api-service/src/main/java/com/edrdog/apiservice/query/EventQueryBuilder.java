package com.edrdog.apiservice.query;

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

    /**
     * tenant 격리 하에 host/type/from/to 필터(옵션)로 최신순 events 조회. limit 은 1..MAX 로 클램프.
     * tenantId 는 필수 — 로그인 유저의 조직 것만 보이도록 항상 WHERE 에 강제된다.
     */
    public ClickHouseQuery events(String tenantId, String host, String type, Long from, Long to, Integer limit) {
        Map<String, String> params = new LinkedHashMap<>();
        String where = where(tenantId, host, type, from, to, params);
        String sql = "SELECT " + COLUMNS + " FROM " + table
                + where
                + " ORDER BY ts DESC LIMIT " + clampLimit(limit);
        return new ClickHouseQuery(sql, params);
    }

    /**
     * tenant 격리 하에 관측된 host 목록과 각 host 의 last_seen(최신 ts)을 뽑는다. tenantId 는 필수.
     * 호스트 대장(registry) 없이 events 집계로만 관측 호스트를 얻는다(엔드포인트 목록의 데이터원).
     */
    public ClickHouseQuery hostsLastSeen(String tenantId) {
        Map<String, String> params = new LinkedHashMap<>();
        String where = where(tenantId, null, null, null, null, params);
        String sql = "SELECT host, max(ts) AS last_seen FROM " + table
                + where
                + " GROUP BY host ORDER BY last_seen DESC";
        return new ClickHouseQuery(sql, params);
    }

    /**
     * lineage 재구성용: tenant+host 격리 하에 시간 윈도우[from,to] events 를 시간순으로 조회.
     * 그래프 빌드에 필요한 컬럼만 뽑고, ts 오름차순(부모->자식 체인 순)으로 정렬한다.
     * 상한(MAX_LIMIT)으로 클램프해 폭주를 막는다. tenantId 는 필수.
     */
    public ClickHouseQuery lineageEvents(String tenantId, String host, Long from, Long to) {
        Map<String, String> params = new LinkedHashMap<>();
        String where = where(tenantId, host, null, from, to, params);
        String sql = "SELECT type, ts, process, parent, dest_ip, dest_port FROM " + table
                + where
                + " ORDER BY ts ASC LIMIT " + MAX_LIMIT;
        return new ClickHouseQuery(sql, params);
    }

    /** tenant 격리 하에 type 별 건수 집계. 시간범위 필터(옵션) 지원. tenantId 는 필수. */
    public ClickHouseQuery summaryByType(String tenantId, Long from, Long to) {
        Map<String, String> params = new LinkedHashMap<>();
        String where = where(tenantId, null, null, from, to, params);
        String sql = "SELECT type, count() AS cnt FROM " + table
                + where
                + " GROUP BY type ORDER BY cnt DESC";
        return new ClickHouseQuery(sql, params);
    }

    /**
     * tenant 격리 하에 시간 윈도우[from,to) 안의 목적지 IP 별 건수를 집계한다(world map 용).
     * 네트워크 이벤트가 아닌 행은 dest_ip 가 ""(빈 문자열)이므로 제외한다. tenantId 는 필수.
     */
    public ClickHouseQuery geo(String tenant, long from, long to) {
        Map<String, String> params = new LinkedHashMap<>();
        String where = where(tenant, null, null, null, null, params);
        params.put("from", String.valueOf(from));
        params.put("to", String.valueOf(to));
        String sql = "SELECT dest_ip, count() AS cnt FROM " + table
                + where
                + " AND ts >= {from:UInt64} AND ts < {to:UInt64} AND dest_ip != ''"
                + " GROUP BY dest_ip";
        return new ClickHouseQuery(sql, params);
    }

    private static String where(String tenantId, String host, String type, Long from, Long to,
                                Map<String, String> params) {
        if (!hasText(tenantId)) {
            throw new IllegalArgumentException("tenant 는 필수입니다(격리)");
        }
        List<String> conds = new ArrayList<>();
        // tenant 격리는 항상 첫 조건으로 강제한다.
        conds.add("tenant_id = {tenant:String}");
        params.put("tenant", tenantId.trim());
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
