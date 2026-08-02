package com.edrdog.apiservice.alert;

import com.edrdog.apiservice.query.ClickHouseQuery;
import com.edrdog.apiservice.query.QueryGuards;
import com.edrdog.apiservice.query.TenantScope;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Locale;

/**
 * alerts(판정기록) 조회/집계 SQL 을 만드는 순수 로직(EventQueryBuilder 와 동일 패턴).
 * 필터값은 파라미터 바인딩({name:Type})으로만 넣는다.
 */
// 모든 SELECT 의 FINAL 은 지우면 ReplacingMergeTree 의 병합 전 중복 행이 그대로 나온다(alert 볼륨이 작아 비용은 무시).
@Component
public class AlertQueryBuilder {

    static final int DEFAULT_LIMIT = 100;
    static final int MAX_LIMIT = 1000;

    /** 컨트롤러가 참조하는 offset 상한(공통 가드와 같은 값). FINAL 이 얹히는 만큼 여기가 더 비싸다. */
    public static final int MAX_OFFSET = QueryGuards.MAX_OFFSET;

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
        return pageScope(tenantId, host, severity, domain, destIp, from, to, includeIds, excludeIds)
                .toQuery("SELECT " + COLUMNS + " FROM " + table + " FINAL",
                        " ORDER BY ts DESC LIMIT " + clampLimit(limit));
    }

    /**
     * 화면 페이지 조회. search 와 같은 WHERE·정렬에 offset 만 얹는다.
     * 호출부는 첫 페이지의 to 를 다음 페이지에 그대로 실어야 한다. 안 그러면 그사이 들어온
     * 알림이 맨 위에 쌓여 offset 이 밀리고 행이 겹치거나 건너뛰어진다.
     */
    public ClickHouseQuery searchPage(String tenantId, String host, String severity, String domain, String destIp,
                                      Long from, Long to, Integer limit, Integer offset,
                                      List<String> includeIds, List<String> excludeIds) {
        // 한 행 더 읽는 탐침. 없으면 다음 페이지 유무를 알려고 FINAL + count() 를 한 번 더 돌아야 한다.
        return pageScope(tenantId, host, severity, domain, destIp, from, to, includeIds, excludeIds)
                .toQuery("SELECT " + COLUMNS + " FROM " + table + " FINAL",
                        " ORDER BY ts DESC LIMIT " + (pageSize(limit) + 1)
                                + QueryGuards.offsetClause(offset, MAX_OFFSET));
    }

    /** searchPage 와 같은 WHERE 로 총 건수만 센다. FINAL 위를 한 번 더 도는 값이라 화면이 요청할 때만 부른다. */
    public ClickHouseQuery countSearch(String tenantId, String host, String severity, String domain, String destIp,
                                       Long from, Long to, List<String> includeIds, List<String> excludeIds) {
        return pageScope(tenantId, host, severity, domain, destIp, from, to, includeIds, excludeIds)
                .toQuery("SELECT count() AS cnt FROM " + table + " FINAL");
    }

    /** 클램프가 적용된 실제 페이지 크기. 호출부가 탐침 행을 잘라내려면 이 값을 알아야 한다. */
    public static int pageSize(Integer limit) {
        return clampLimit(limit);
    }

    /** searchPage 와 countSearch 가 같은 WHERE 를 쓰도록 조건 조립을 한곳에 둔다. */
    private static TenantScope pageScope(String tenantId, String host, String severity, String domain, String destIp,
                                         Long from, Long to, List<String> includeIds, List<String> excludeIds) {
        TenantScope scope = base(tenantId, host, severity, from, to);
        addDomain(domain, scope);
        addDestIp(destIp, scope);
        return scope
                .addIn("id", "inc", includeIds)
                .addNotIn("id", "exc", excludeIds);
    }

    /** tenant 격리 하에 단건 조회(존재/소유 확인용). 없으면 빈 결과. */
    public ClickHouseQuery byId(String tenantId, String id) {
        return base(tenantId, null, null, null, null)
                .add("id = {id:String}", "id", id)
                .toQuery("SELECT " + COLUMNS + " FROM " + table + " FINAL", " LIMIT 1");
    }

    /** 기간 내 severity 별 카운트(대시보드 분포용). from/to 는 null 이면 무시. */
    public ClickHouseQuery countBySeverity(String tenantId, Long from, Long to) {
        return base(tenantId, null, null, from, to)
                .toQuery("SELECT severity, count() AS cnt FROM " + table + " FINAL", " GROUP BY severity");
    }

    /** 기간 내 ruleId 별 카운트(대시보드 카테고리 접기용). from/to 는 null 이면 무시. */
    public ClickHouseQuery countByRuleId(String tenantId, Long from, Long to) {
        return base(tenantId, null, null, from, to)
                .toQuery("SELECT rule_id, count() AS cnt FROM " + table + " FINAL", " GROUP BY rule_id");
    }

    /** 기간 내 버킷(bucketMs 간격)×severity 별 카운트(대시보드 timeseries 용). */
    public ClickHouseQuery timeseries(String tenantId, long from, long to, long bucketMs) {
        // 버킷 경계는 TimeseriesFill.alignStart 와 같은 규칙(UTC 정렬)이라야 0 채우기와 어긋나지 않는다.
        return base(tenantId, null, null, from, to)
                .toQuery("SELECT intDiv(ts, " + bucketMs + ") * " + bucketMs + " AS bucketStart, "
                                + "severity, count() AS cnt FROM " + table + " FINAL",
                        " GROUP BY bucketStart, severity");
    }

    /** host 별 열린 alert 집계(엔드포인트 목록 status/위협수용). excludeIds(트리아지된 id)를 빼서 open 만 센다. */
    public ClickHouseQuery openHostCounts(String tenantId, List<String> excludeIds) {
        return base(tenantId, null, null, null, null)
                .addNotIn("id", "exc", excludeIds)
                .toQuery("SELECT host, count() AS openTotal, "
                        + "countIf(severity = 'CRITICAL') AS openCritical, "
                        + "countIf(severity = 'HIGH') AS openHigh "
                        + "FROM " + table + " FINAL", " GROUP BY host");
    }

    /** tenant(필수) + host/severity/from/to(옵션) 공통 조건. tenant 는 조립기 생성 시점에 강제된다. */
    private static TenantScope base(String tenantId, String host, String severity, Long from, Long to) {
        return TenantScope.of(tenantId)
                .addIfText("host = {host:String}", "host", host)
                .addIfText("severity = {severity:String}", "severity", severity)
                .addIfPresent("ts >= {from:UInt64}", "from", from)
                .addIfPresent("ts < {to:UInt64}", "to", to);
    }

    /** domain 필터. */
    private static void addDomain(String domain, TenantScope scope) {
        // host/severity 와 달리 빈 문자열을 hasText 로 걸러내면 목적지를 관측 못한 알림을 찾을 방법이 없어진다.
        if (domain == null) {
            return;
        }
        // 적재 측(agent 의 normalizeDNSName)이 소문자로 정규화한다. 안 맞추면 대문자 검색어가 못 찾는다.
        scope.add("domain = {domain:String}", "domain", domain.trim().toLowerCase(Locale.ROOT));
    }

    /** destIp 필터. */
    private static void addDestIp(String destIp, TenantScope scope) {
        // domain 과 같은 이유로 빈 문자열을 걸러내지 않는다.
        if (destIp == null) {
            return;
        }
        // 적재 측(Go 의 net.IP.String())이 소문자로 쓴다. IPv6 16진수가 대문자로 들어오면 못 찾는다.
        scope.add("dest_ip = {destIp:String}", "destIp", destIp.trim().toLowerCase(Locale.ROOT));
    }

    private static int clampLimit(Integer limit) {
        return QueryGuards.clampLimit(limit, DEFAULT_LIMIT, MAX_LIMIT);
    }
}
