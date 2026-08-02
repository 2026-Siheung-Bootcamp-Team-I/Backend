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
 * 필터값은 파라미터 바인딩({name:Type})으로만 넣는다.
 */
// 모든 SELECT 의 FINAL 은 지우면 ReplacingMergeTree 의 병합 전 중복 행이 그대로 나온다(alert 볼륨이 작아 비용은 무시).
@Component
public class AlertQueryBuilder {

    static final int DEFAULT_LIMIT = 100;
    static final int MAX_LIMIT = 1000;

    // offset 상한. ClickHouse 의 OFFSET 은 건너뛸 행을 실제로 읽고, FINAL 이 얹혀 여기가 더 비싸다.
    public static final int MAX_OFFSET = 10_000;

    // 조회 컬럼. domain/dest_ip 가 빠지면 어느 목적지 때문에 걸렸는지를 셀 수 없다.
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

    /** 필터 조회. includeIds/excludeIds 는 오버레이(MySQL) status 필터를 SQL IN/NOT IN 으로 옮긴 것이다. */
    public ClickHouseQuery search(String tenantId, String host, String severity, String domain, String destIp,
                                  Long from, Long to, Integer limit, List<String> includeIds, List<String> excludeIds) {
        Map<String, String> params = new LinkedHashMap<>();
        List<String> conds = pageConds(tenantId, host, severity, domain, destIp, from, to,
                includeIds, excludeIds, params);
        String sql = "SELECT " + COLUMNS + " FROM " + table + " FINAL"
                + where(conds)
                + " ORDER BY ts DESC LIMIT " + clampLimit(limit);
        return new ClickHouseQuery(sql, params);
    }

    /**
     * 화면 페이지 조회. search 와 같은 WHERE·정렬에 offset 만 얹는다.
     * 호출부는 첫 페이지의 to 를 다음 페이지에 그대로 실어야 한다. 안 그러면 그사이 들어온
     * 알림이 맨 위에 쌓여 offset 이 밀리고 행이 겹치거나 건너뛰어진다.
     */
    public ClickHouseQuery searchPage(String tenantId, String host, String severity, String domain, String destIp,
                                      Long from, Long to, Integer limit, Integer offset,
                                      List<String> includeIds, List<String> excludeIds) {
        Map<String, String> params = new LinkedHashMap<>();
        List<String> conds = pageConds(tenantId, host, severity, domain, destIp, from, to,
                includeIds, excludeIds, params);
        // 한 행 더 읽는 탐침. 없으면 다음 페이지 유무를 알려고 FINAL + count() 를 한 번 더 돌아야 한다.
        String sql = "SELECT " + COLUMNS + " FROM " + table + " FINAL"
                + where(conds)
                + " ORDER BY ts DESC LIMIT " + (pageSize(limit) + 1)
                + offsetClause(offset);
        return new ClickHouseQuery(sql, params);
    }

    /** searchPage 와 같은 WHERE 로 총 건수만 센다. FINAL 위를 한 번 더 도는 값이라 화면이 요청할 때만 부른다. */
    public ClickHouseQuery countSearch(String tenantId, String host, String severity, String domain, String destIp,
                                       Long from, Long to, List<String> includeIds, List<String> excludeIds) {
        Map<String, String> params = new LinkedHashMap<>();
        List<String> conds = pageConds(tenantId, host, severity, domain, destIp, from, to,
                includeIds, excludeIds, params);
        return new ClickHouseQuery("SELECT count() AS cnt FROM " + table + " FINAL" + where(conds), params);
    }

    /** 클램프가 적용된 실제 페이지 크기. 호출부가 탐침 행을 잘라내려면 이 값을 알아야 한다. */
    public static int pageSize(Integer limit) {
        return clampLimit(limit);
    }

    /** searchPage 와 countSearch 가 같은 WHERE 를 쓰도록 조건 조립을 한곳에 둔다. */
    private static List<String> pageConds(String tenantId, String host, String severity, String domain, String destIp,
                                          Long from, Long to, List<String> includeIds, List<String> excludeIds,
                                          Map<String, String> params) {
        List<String> conds = base(tenantId, host, severity, from, to, params);
        addDomain(domain, conds, params);
        addDestIp(destIp, conds, params);
        addIdSet("inc", includeIds, false, conds, params);
        addIdSet("exc", excludeIds, true, conds, params);
        return conds;
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

    /** 기간 내 severity 별 카운트(대시보드 분포용). from/to 는 null 이면 무시. */
    public ClickHouseQuery countBySeverity(String tenantId, Long from, Long to) {
        Map<String, String> params = new LinkedHashMap<>();
        List<String> conds = base(tenantId, null, null, from, to, params);
        String sql = "SELECT severity, count() AS cnt FROM " + table + " FINAL"
                + where(conds) + " GROUP BY severity";
        return new ClickHouseQuery(sql, params);
    }

    /** 기간 내 ruleId 별 카운트(대시보드 카테고리 접기용). from/to 는 null 이면 무시. */
    public ClickHouseQuery countByRuleId(String tenantId, Long from, Long to) {
        Map<String, String> params = new LinkedHashMap<>();
        List<String> conds = base(tenantId, null, null, from, to, params);
        String sql = "SELECT rule_id, count() AS cnt FROM " + table + " FINAL"
                + where(conds) + " GROUP BY rule_id";
        return new ClickHouseQuery(sql, params);
    }

    /** 기간 내 버킷(bucketMs 간격)×severity 별 카운트(대시보드 timeseries 용). */
    public ClickHouseQuery timeseries(String tenantId, long from, long to, long bucketMs) {
        Map<String, String> params = new LinkedHashMap<>();
        List<String> conds = base(tenantId, null, null, from, to, params);
        // 버킷 경계는 TimeseriesFill.alignStart 와 같은 규칙(UTC 정렬)이라야 0 채우기와 어긋나지 않는다.
        String sql = "SELECT intDiv(ts, " + bucketMs + ") * " + bucketMs + " AS bucketStart, "
                + "severity, count() AS cnt FROM " + table + " FINAL"
                + where(conds) + " GROUP BY bucketStart, severity";
        return new ClickHouseQuery(sql, params);
    }

    /** host 별 열린 alert 집계(엔드포인트 목록 status/위협수용). excludeIds(트리아지된 id)를 빼서 open 만 센다. */
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
        // 이 검사를 빼면 tenant 없는 호출이 조직 전체 알림을 그대로 읽는다.
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

    /** domain 필터. */
    private static void addDomain(String domain, List<String> conds, Map<String, String> params) {
        // host/severity 와 달리 빈 문자열을 hasText 로 걸러내면 목적지를 관측 못한 알림을 찾을 방법이 없어진다.
        if (domain == null) {
            return;
        }
        // 적재 측(agent 의 normalizeDNSName)이 소문자로 정규화한다. 안 맞추면 대문자 검색어가 못 찾는다.
        conds.add("domain = {domain:String}");
        params.put("domain", domain.trim().toLowerCase(Locale.ROOT));
    }

    /** destIp 필터. */
    private static void addDestIp(String destIp, List<String> conds, Map<String, String> params) {
        // domain 과 같은 이유로 빈 문자열을 걸러내지 않는다.
        if (destIp == null) {
            return;
        }
        // 적재 측(Go 의 net.IP.String())이 소문자로 쓴다. IPv6 16진수가 대문자로 들어오면 못 찾는다.
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

    /** limit 과 달리 범위 밖 offset 은 클램프하지 않고 거절한다(조용히 자르면 화면이 빈 페이지로 읽는다). */
    private static String offsetClause(Integer offset) {
        if (offset == null || offset == 0) {
            return "";
        }
        if (offset < 0 || offset > MAX_OFFSET) {
            throw new IllegalArgumentException("offset 은 0..." + MAX_OFFSET + " 여야 합니다: " + offset);
        }
        return " OFFSET " + offset;
    }

    private static boolean hasText(String s) {
        return s != null && !s.trim().isEmpty();
    }
}
