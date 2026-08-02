package com.edrdog.apiservice.intelligence.correlate;

import com.edrdog.apiservice.query.ClickHouseQuery;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 상관분석용 events 조회 SQL 을 만드는 순수 로직(EventQueryBuilder 와 같은 규칙).
 * 필터는 파라미터 바인딩으로만 넣고, tenant 는 없으면 예외를 던져 격리를 강제한다.
 */
@Component
public class CorrelateQueryBuilder {

    static final int DEFAULT_LIMIT = 500;

    /** 클라이언트가 준 limit 은 이 값으로 자른다. 상한을 풀면 한 요청이 events 를 통째로 끌어간다. */
    static final int MAX_LIMIT = 2000;

    /** IN 절이 끝없이 길어지지 않게 자르는 상한. 응답 IP 가 아주 많은 도메인이 있다. */
    static final int MAX_DEST_IPS = 64;

    // EventResponse.fromRow 가 읽는 컬럼 전부. 여기서 detail 파싱을 다시 구현하지 않고 그 DTO 를 그대로 쓴다.
    private static final String COLUMNS =
            "host, type, ts, process, parent, cmdline, dest_ip, dest_port, domain, detail, sha256, ingested_at";

    /** 관계를 만들 수 있는 타입만 본다. process/file/script 는 도메인·IP 축을 갖지 않는다. */
    private static final String SEED_TYPES = "type IN ('dns', 'network', 'l7')";
    private static final String CONNECT_TYPES = "type IN ('network', 'l7')";

    private final String table;

    public CorrelateQueryBuilder(@Value("${edrdog.clickhouse.table}") String table) {
        this.table = table;
    }

    /** 기준점(도메인 또는 IP)과 얽힌 이벤트를 조회한다. */
    public ClickHouseQuery seedEvents(String tenantId, CorrelateTarget target, Long from, Long to, Integer limit) {
        Map<String, String> params = new LinkedHashMap<>();
        List<String> conds = tenantScoped(tenantId, params);
        conds.add(SEED_TYPES);
        // IP 기준점에서 answers 조건을 빼면 "어느 도메인이 이 IP 로 풀렸나"를 놓친다.
        conds.add(target.kind() == TargetKind.DOMAIN
                ? "domain = {seed:String}"
                : "(dest_ip = {seed:String} OR has(JSONExtract(detail, 'answers', 'Array(String)'), {seed:String}))");
        params.put("seed", target.value());
        addRange(conds, params, from, to);

        String sql = "SELECT " + COLUMNS + " FROM " + table
                + " WHERE " + String.join(" AND ", conds)
                + " ORDER BY ts DESC LIMIT " + clampLimit(limit);
        return new ClickHouseQuery(sql, params);
    }

    /**
     * 프로세스 보정 후보 조회: 주어진 IP 들로 실제로 붙은 접속 이벤트.
     * 호스트·시간 창을 여기서 좁히면 이벤트마다 조회가 갈려 질의가 수십 번 나간다(DnsProcessBackfill 이 맞춘다).
     */
    public ClickHouseQuery destinationEvents(String tenantId, List<String> destIps, long from, long to) {
        Map<String, String> params = new LinkedHashMap<>();
        List<String> conds = tenantScoped(tenantId, params);
        if (destIps.isEmpty()) {
            throw new IllegalArgumentException("보정할 목적지 IP 가 없습니다");
        }
        conds.add(CONNECT_TYPES);

        List<String> placeholders = new ArrayList<>();
        List<String> capped = destIps.size() > MAX_DEST_IPS ? destIps.subList(0, MAX_DEST_IPS) : destIps;
        for (int i = 0; i < capped.size(); i++) {
            placeholders.add("{ip" + i + ":String}");
            params.put("ip" + i, capped.get(i));
        }
        conds.add("dest_ip IN (" + String.join(", ", placeholders) + ")");
        conds.add("ts >= {from:UInt64}");
        conds.add("ts <= {to:UInt64}");
        params.put("from", String.valueOf(from));
        params.put("to", String.valueOf(to));

        String sql = "SELECT " + COLUMNS + " FROM " + table
                + " WHERE " + String.join(" AND ", conds)
                + " ORDER BY ts ASC LIMIT " + MAX_LIMIT;
        return new ClickHouseQuery(sql, params);
    }

    /** tenant 격리는 항상 첫 조건으로 강제한다. 없으면 조회 자체를 만들지 않는다. */
    private static List<String> tenantScoped(String tenantId, Map<String, String> params) {
        if (tenantId == null || tenantId.trim().isEmpty()) {
            throw new IllegalArgumentException("tenant 는 필수입니다(격리)");
        }
        List<String> conds = new ArrayList<>();
        conds.add("tenant_id = {tenant:String}");
        params.put("tenant", tenantId.trim());
        return conds;
    }

    private static void addRange(List<String> conds, Map<String, String> params, Long from, Long to) {
        if (from != null) {
            conds.add("ts >= {from:UInt64}");
            params.put("from", String.valueOf(from));
        }
        if (to != null) {
            conds.add("ts <= {to:UInt64}");
            params.put("to", String.valueOf(to));
        }
    }

    private static int clampLimit(Integer limit) {
        if (limit == null || limit <= 0) {
            return DEFAULT_LIMIT;
        }
        return Math.min(limit, MAX_LIMIT);
    }
}
