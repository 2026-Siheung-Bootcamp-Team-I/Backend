package com.edrdog.apiservice.intelligence.topology;

import com.edrdog.apiservice.query.ClickHouseQuery;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * egress 토폴로지(엔드포인트→목적지) 집계 SQL 을 만드는 순수 로직
 * (EventQueryBuilder/AlertQueryBuilder 와 동일 패턴: 값은 파라미터 바인딩, tenant 는 항상 필수).
 * 목적지를 domain/dest_ip 한 칸으로 합치지 않으면 dns 와 network 이벤트가 같은 관계를 두 노드로 가른다.
 */
@Component
public class TopologyQueryBuilder {

    /** 그래프는 엣지가 수백 개를 넘으면 사람이 읽지 못한다. 기본은 좁게, 상한은 폭주 방지선으로 둔다. */
    static final int DEFAULT_LIMIT = 200;
    static final int MAX_LIMIT = 1000;

    private static final String DEST = "if(domain != '', domain, dest_ip)";
    private static final String HAS_DEST = "(domain != '' OR dest_ip != '')";

    private final String eventsTable;
    private final String alertsTable;

    public TopologyQueryBuilder(@Value("${edrdog.clickhouse.table}") String eventsTable,
                                @Value("${edrdog.clickhouse.alerts-table}") String alertsTable) {
        this.eventsTable = eventsTable;
        this.alertsTable = alertsTable;
    }

    /**
     * 기간[from,to) 안의 (host, 목적지) 관계를 이벤트 많은 순으로 Top-N 만 뽑는다.
     * 프로토콜은 detail 안에 있어 l4(protocol)와 l7(l7Protocol)을 각각 꺼내 관측된 값만 모은다.
     */
    public ClickHouseQuery egressRelations(String tenantId, long from, long to, String search, Integer limit) {
        Map<String, String> params = new LinkedHashMap<>();
        List<String> conds = base(tenantId, from, to, params);
        conds.add(HAS_DEST);
        addSearch(search, conds, params);
        String sql = "SELECT host, " + DEST + " AS dest, "
                + "if(domain != '', 'domain', 'ip') AS destKind, "
                + "count() AS events, max(ts) AS lastSeen, "
                + "groupUniqArray(8)(JSONExtractString(detail, 'protocol')) AS protocols, "
                + "groupUniqArray(8)(JSONExtractString(detail, 'l7Protocol')) AS l7Protocols"
                + " FROM " + eventsTable + where(conds)
                + " GROUP BY host, dest, destKind ORDER BY events DESC LIMIT " + clampLimit(limit);
        return new ClickHouseQuery(sql, params);
    }

    /**
     * 자르기 전 전체 관계 수. Top-N 으로 잘라 놓고 전체 수를 말하지 않으면 화면이 "이게 전부" 로 읽힌다.
     * egressRelations 와 같은 조건(기간·검색어)으로 세야 같은 모집단의 부분집합이 된다.
     */
    public ClickHouseQuery relationTotal(String tenantId, long from, long to, String search) {
        Map<String, String> params = new LinkedHashMap<>();
        List<String> conds = base(tenantId, from, to, params);
        conds.add(HAS_DEST);
        addSearch(search, conds, params);
        String sql = "SELECT uniqExact((host, " + DEST + ")) AS total FROM " + eventsTable + where(conds);
        return new ClickHouseQuery(sql, params);
    }

    /** 관계별 알림 수. 엣지가 실선(알림 있음)인지 점선(관측만)인지를 가른다. 트리아지된 알림도 빼지 않는다. */
    public ClickHouseQuery relationAlertCounts(String tenantId, long from, long to) {
        Map<String, String> params = new LinkedHashMap<>();
        List<String> conds = base(tenantId, from, to, params);
        conds.add(HAS_DEST);
        // FINAL 을 빼면 ReplacingMergeTree dedup 이 안 돼 같은 알림이 여러 번 세진다.
        String sql = "SELECT host, " + DEST + " AS dest, count() AS alerts"
                + " FROM " + alertsTable + " FINAL" + where(conds) + " GROUP BY host, dest";
        return new ClickHouseQuery(sql, params);
    }

    /** tenant(필수) + 기간[from,to) 공통 조건. tenant 격리는 항상 첫 조건으로 강제한다. */
    private static List<String> base(String tenantId, long from, long to, Map<String, String> params) {
        if (tenantId == null || tenantId.trim().isEmpty()) {
            throw new IllegalArgumentException("tenant 는 필수입니다(격리)");
        }
        List<String> conds = new ArrayList<>();
        conds.add("tenant_id = {tenant:String}");
        params.put("tenant", tenantId.trim());
        conds.add("ts >= {from:UInt64}");
        params.put("from", String.valueOf(from));
        conds.add("ts < {to:UInt64}");
        params.put("to", String.valueOf(to));
        return conds;
    }

    /** 검색어는 host/domain/dest_ip 부분일치. 값에 든 LIKE 와일드카드는 문자로 찾도록 이스케이프한다. */
    private static void addSearch(String search, List<String> conds, Map<String, String> params) {
        if (search == null || search.trim().isEmpty()) {
            return;
        }
        conds.add("(host ILIKE {q:String} OR domain ILIKE {q:String} OR dest_ip ILIKE {q:String})");
        params.put("q", "%" + escapeLike(search.trim()) + "%");
    }

    /** 사용자가 넣은 %/_ 를 그대로 두면 검색어 하나가 전체 매치가 된다. 역슬래시부터 먼저 바꾼다. */
    private static String escapeLike(String s) {
        return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_");
    }

    private static String where(List<String> conds) {
        return " WHERE " + String.join(" AND ", conds);
    }

    private static int clampLimit(Integer limit) {
        if (limit == null || limit <= 0) {
            return DEFAULT_LIMIT;
        }
        return Math.min(limit, MAX_LIMIT);
    }
}
