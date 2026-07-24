package com.edrdog.apiservice.alert;

import com.edrdog.apiservice.query.ClickHouseQuery;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * alerts(판정기록) 조회/집계 SQL 을 만드는 순수 로직(EventQueryBuilder 와 동일 패턴).
 * 필터값은 파라미터 바인딩({name:Type})으로만 넣고, tenant 는 항상 필수라 조직 격리를 강제한다.
 * 모든 SELECT 는 ReplacingMergeTree dedup 을 위해 FROM alerts FINAL 을 쓴다(alert 볼륨이 작아 비용 무시).
 */
@Component
public class AlertQueryBuilder {

    static final int DEFAULT_LIMIT = 100;
    static final int MAX_LIMIT = 1000;

    private static final String COLUMNS =
            "id, tenant_id, host, rule_id, mitre, severity, action, ts, matched";

    private final String table;

    public AlertQueryBuilder(@Value("${edrdog.clickhouse.alerts-table}") String table) {
        this.table = table;
    }

    /**
     * tenant 격리 하에 host/severity/시간범위(옵션) 필터로 최신순 조회. limit 은 1..MAX 로 클램프.
     * includeIds 가 있으면 그 id 집합으로만 좁히고(id IN), excludeIds 가 있으면 그 집합을 뺀다(id NOT IN).
     * 두 목록은 오버레이(MySQL)에서 계산한 status 필터를 SQL 로 옮긴 것이다(빈 목록이면 해당 조건 생략).
     */
    public ClickHouseQuery search(String tenantId, String host, String severity, Long from, Long to,
                                  Integer limit, List<String> includeIds, List<String> excludeIds) {
        Map<String, String> params = new LinkedHashMap<>();
        List<String> conds = base(tenantId, host, severity, from, to, params);
        addIdSet("inc", includeIds, false, conds, params);
        addIdSet("exc", excludeIds, true, conds, params);
        String sql = "SELECT " + COLUMNS + " FROM " + table + " FINAL"
                + where(conds)
                + " ORDER BY ts DESC LIMIT " + clampLimit(limit);
        return new ClickHouseQuery(sql, params);
    }

    /** tenant 격리 하에 단건 조회(존재/소유 확인용). 없으면 빈 결과. */
    public ClickHouseQuery byId(String tenantId, String id) {
        Map<String, String> params = new LinkedHashMap<>();
        List<String> conds = base(tenantId, null, null, null, null, params);
        conds.add("id = {id:String}");
        params.put("id", id);
        String sql = "SELECT " + COLUMNS + " FROM " + table + " FINAL"
                + where(conds) + " LIMIT 1";
        return new ClickHouseQuery(sql, params);
    }

    /** 기간 내 severity 별 카운트(대시보드 분포용). tenant 격리 필수, from/to 는 null 이면 무시. */
    public ClickHouseQuery countBySeverity(String tenantId, Long from, Long to) {
        Map<String, String> params = new LinkedHashMap<>();
        List<String> conds = base(tenantId, null, null, from, to, params);
        String sql = "SELECT severity, count() AS cnt FROM " + table + " FINAL"
                + where(conds) + " GROUP BY severity";
        return new ClickHouseQuery(sql, params);
    }

    /** 기간 내 ruleId 별 카운트(대시보드 카테고리 접기용). tenant 격리 필수, from/to 는 null 이면 무시. */
    public ClickHouseQuery countByRuleId(String tenantId, Long from, Long to) {
        Map<String, String> params = new LinkedHashMap<>();
        List<String> conds = base(tenantId, null, null, from, to, params);
        String sql = "SELECT rule_id, count() AS cnt FROM " + table + " FINAL"
                + where(conds) + " GROUP BY rule_id";
        return new ClickHouseQuery(sql, params);
    }

    /**
     * 기간 내 버킷(bucketMs 간격)×severity 별 카운트(대시보드 timeseries 용). tenant 격리 필수.
     * bucketStart = intDiv(ts, bucketMs) * bucketMs (UTC 정렬, TimeseriesFill.alignStart 와 동일 규칙).
     */
    public ClickHouseQuery timeseries(String tenantId, long from, long to, long bucketMs) {
        Map<String, String> params = new LinkedHashMap<>();
        List<String> conds = base(tenantId, null, null, from, to, params);
        String sql = "SELECT intDiv(ts, " + bucketMs + ") * " + bucketMs + " AS bucketStart, "
                + "severity, count() AS cnt FROM " + table + " FINAL"
                + where(conds) + " GROUP BY bucketStart, severity";
        return new ClickHouseQuery(sql, params);
    }

    /**
     * host 별 열린 alert 집계(엔드포인트 목록 status/위협수용). tenant 격리 필수.
     * excludeIds(오버레이에 트리아지된 id) 를 빼서 "열린(open)" 것만 센다(빈 목록이면 전부가 열린 것).
     */
    public ClickHouseQuery openHostCounts(String tenantId, List<String> excludeIds) {
        Map<String, String> params = new LinkedHashMap<>();
        List<String> conds = base(tenantId, null, null, null, null, params);
        addIdSet("exc", excludeIds, true, conds, params);
        String sql = "SELECT host, count() AS openTotal, "
                + "countIf(severity = 'CRITICAL') AS openCritical, "
                + "countIf(severity = 'HIGH') AS openHigh "
                + "FROM " + table + " FINAL" + where(conds) + " GROUP BY host";
        return new ClickHouseQuery(sql, params);
    }

    /** tenant(필수) + host/severity/from/to(옵션) 공통 조건. tenant 는 항상 첫 조건으로 강제한다. */
    private static List<String> base(String tenantId, String host, String severity, Long from, Long to,
                                     Map<String, String> params) {
        if (!hasText(tenantId)) {
            throw new IllegalArgumentException("tenant 는 필수입니다(격리)");
        }
        List<String> conds = new ArrayList<>();
        conds.add("tenant_id = {tenant:String}");
        params.put("tenant", tenantId.trim());
        if (hasText(host)) {
            conds.add("host = {host:String}");
            params.put("host", host.trim());
        }
        if (hasText(severity)) {
            conds.add("severity = {severity:String}");
            params.put("severity", severity.trim());
        }
        if (from != null) {
            conds.add("ts >= {from:UInt64}");
            params.put("from", String.valueOf(from));
        }
        if (to != null) {
            conds.add("ts < {to:UInt64}");
            params.put("to", String.valueOf(to));
        }
        return conds;
    }

    /** id IN/NOT IN 조건을 개별 파라미터 바인딩으로 추가한다. null 이거나 비어 있으면 아무것도 안 한다. */
    private static void addIdSet(String key, List<String> ids, boolean negate,
                                 List<String> conds, Map<String, String> params) {
        if (ids == null || ids.isEmpty()) {
            return;
        }
        List<String> placeholders = new ArrayList<>();
        for (int i = 0; i < ids.size(); i++) {
            String name = key + i;
            placeholders.add("{" + name + ":String}");
            params.put(name, ids.get(i));
        }
        conds.add("id " + (negate ? "NOT IN" : "IN") + " (" + String.join(", ", placeholders) + ")");
    }

    private static String where(List<String> conds) {
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
