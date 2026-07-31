package com.edrdog.apiservice.alert;

import com.edrdog.apiservice.query.ClickHouseQuery;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
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

    // domain/dest_ip 는 판정을 유발한 목적지. "이 엔드포인트가 어디에 붙어서 걸렸나" 를 세려면 조회 컬럼에 있어야 한다.
    private static final String COLUMNS =
            "id, tenant_id, host, rule_id, mitre, severity, action, ts, matched, domain, dest_ip";

    private final String table;

    public AlertQueryBuilder(@Value("${edrdog.clickhouse.alerts-table}") String table) {
        this.table = table;
    }

    /** domain/destIp 없이 부르는 기존 호출부(IncidentService 등) 호환용. 새 필터는 안 건다. */
    public ClickHouseQuery search(String tenantId, String host, String severity, Long from, Long to,
                                  Integer limit, List<String> includeIds, List<String> excludeIds) {
        return search(tenantId, host, severity, null, null, from, to, limit, includeIds, excludeIds);
    }

    /**
     * includeIds/excludeIds 는 오버레이(MySQL)에서 계산한 status 필터를 SQL IN/NOT IN 으로 옮긴 것이다(빈 목록이면 조건 생략).
     * domain/destIp 는 알림이 실은 목적지(관계 분석 화면에서 도메인을 짚었을 때 그 도메인 때문에 난 알림을 찾는 용도).
     */
    public ClickHouseQuery search(String tenantId, String host, String severity, String domain, String destIp,
                                  Long from, Long to, Integer limit, List<String> includeIds, List<String> excludeIds) {
        Map<String, String> params = new LinkedHashMap<>();
        List<String> conds = base(tenantId, host, severity, from, to, params);
        addDomain(domain, conds, params);
        addDestIp(destIp, conds, params);
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

    /**
     * domain 필터. host/severity 와 달리 미지정(null)과 빈 문자열 필터링을 구분한다: 목적지를 관측 못한 alert 는
     * domain 이 빈 문자열로 적재되므로, 빈 값으로도 걸러야 그 알림들을 찾을 수 있다.
     * 도메인은 소문자로 정규화되어 적재되므로(agent 의 normalizeDNSName) 검색어도 소문자로 맞춘다(EventQueryBuilder.sha256 과 동일 패턴).
     */
    private static void addDomain(String domain, List<String> conds, Map<String, String> params) {
        if (domain == null) {
            return;
        }
        conds.add("domain = {domain:String}");
        params.put("domain", domain.trim().toLowerCase(Locale.ROOT));
    }

    /**
     * destIp 필터. domain 과 같은 이유로 미지정과 빈 문자열을 구분한다.
     * IPv6 는 16진수라 대소문자가 같은 주소를 가리킨다(Go 의 net.IP.String() 은 항상 소문자로 적재한다).
     * IPv4 는 글자가 없어 영향 없고 IPv6 만 이득이라 domain 과 같이 소문자로 맞춘다.
     */
    private static void addDestIp(String destIp, List<String> conds, Map<String, String> params) {
        if (destIp == null) {
            return;
        }
        conds.add("dest_ip = {destIp:String}");
        params.put("destIp", destIp.trim().toLowerCase(Locale.ROOT));
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
