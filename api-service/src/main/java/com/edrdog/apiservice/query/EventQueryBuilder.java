package com.edrdog.apiservice.query;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Locale;

/**
 * events 조회/요약 SQL 을 만드는 순수 로직. 필터는 파라미터 바인딩으로만 넣고, limit 은 상한으로 클램프한다.
 */
@Component
public class EventQueryBuilder {

    static final int DEFAULT_LIMIT = 100;
    static final int MAX_LIMIT = 1000;

    /** 컨트롤러가 참조하는 offset 상한(공통 가드와 같은 값). */
    public static final int MAX_OFFSET = QueryGuards.MAX_OFFSET;

    // 조회 컬럼. domain/detail(dns/l7)·sha256 이 빠지면 무엇에 걸린 건지 화면에서 확인할 수 없다.
    private static final String COLUMNS =
            "host, type, ts, process, parent, cmdline, dest_ip, dest_port, domain, detail, sha256, ingested_at";

    private final String table;

    public EventQueryBuilder(@Value("${edrdog.clickhouse.table}") String table) {
        this.table = table;
    }

    /** tenant 격리 하에 host/type/sha256/from/to 필터(옵션)로 최신순 events 조회. limit 은 1..MAX 로 클램프. */
    public ClickHouseQuery events(String tenantId, String host, String type, String sha256,
                                  Long from, Long to, Integer limit) {
        return scope(tenantId, host, type, sha256, from, to)
                .toQuery("SELECT " + COLUMNS + " FROM " + table,
                        " ORDER BY ts DESC LIMIT " + clampLimit(limit));
    }

    /**
     * 화면 페이지 조회. events() 와 같은 WHERE·정렬에 offset 만 얹는다.
     * 호출부는 첫 페이지의 to 를 다음 페이지에 그대로 실어야 한다. 안 그러면 그사이 들어온
     * 이벤트가 맨 위에 쌓여 offset 이 밀리고 행이 겹치거나 건너뛰어진다.
     */
    public ClickHouseQuery eventsPage(String tenantId, String host, String type, String sha256,
                                      Long from, Long to, Integer limit, Integer offset) {
        // 한 행 더 읽는 탐침. 없으면 다음 페이지 유무를 알려고 count() 를 한 번 더 돌아야 한다.
        return scope(tenantId, host, type, sha256, from, to)
                .toQuery("SELECT " + COLUMNS + " FROM " + table,
                        " ORDER BY ts DESC LIMIT " + (pageSize(limit) + 1)
                                + QueryGuards.offsetClause(offset, MAX_OFFSET));
    }

    /** eventsPage 와 같은 WHERE 로 총 건수만 센다(tenant 격리도 그대로라 남의 조직은 총계에 안 섞인다). */
    public ClickHouseQuery countEvents(String tenantId, String host, String type, String sha256,
                                       Long from, Long to) {
        return scope(tenantId, host, type, sha256, from, to)
                .toQuery("SELECT count() AS cnt FROM " + table);
    }

    /** 클램프가 적용된 실제 페이지 크기. 호출부가 탐침 행을 잘라내려면 이 값을 알아야 한다. */
    public static int pageSize(Integer limit) {
        return clampLimit(limit);
    }

    /** tenant 격리 하에 관측된 host 목록과 각 host 의 last_seen(최신 ts). 엔드포인트 목록의 데이터원이다. */
    public ClickHouseQuery hostsLastSeen(String tenantId) {
        return scope(tenantId, null, null, null, null, null)
                .toQuery("SELECT host, max(ts) AS last_seen FROM " + table,
                        " GROUP BY host ORDER BY last_seen DESC");
    }

    /** lineage 재구성용: tenant+host 격리 하에 [from,to] events 를 ts 오름차순(부모->자식 체인 순)으로 조회. */
    public ClickHouseQuery lineageEvents(String tenantId, String host, Long from, Long to) {
        // detail 을 빼면 그 안에 든 pid/ppid 를 못 써서 동명 프로세스가 한 노드로 붙는다.
        return scope(tenantId, host, null, null, from, to)
                .toQuery("SELECT type, ts, process, parent, dest_ip, dest_port, detail FROM " + table,
                        " ORDER BY ts ASC LIMIT " + MAX_LIMIT);
    }

    // 단건(id) 조회용 창의 반폭(ms). 링크가 나르는 ts 는 원본과 몇 ms 어긋나 점으로 잡으면 조용히 404 가 된다.
    static final long POINT_WINDOW_MS = 1000;

    /**
     * tenant+host 격리 하에 ts 주변 좁은 창의 events 를 뽑는다(id 로 단건을 지목하는 경로).
     * events 에 id 컬럼이 없어 후보만 좁히고 id 대조는 호출부가 한다.
     */
    public ClickHouseQuery eventAt(String tenantId, String host, long ts) {
        // host 가 없으면 tenant 전체를 훑는다.
        if (!QueryGuards.hasText(host)) {
            throw new IllegalArgumentException("host 는 필수입니다(단건 조회 범위)");
        }
        return scope(tenantId, host, null, null, Math.max(0, ts - POINT_WINDOW_MS), ts + POINT_WINDOW_MS)
                .toQuery("SELECT " + COLUMNS + " FROM " + table,
                        " ORDER BY ts DESC LIMIT " + MAX_LIMIT);
    }

    /** tenant 격리 하에 type 별 건수 집계. 시간범위 필터(옵션) 지원. */
    public ClickHouseQuery summaryByType(String tenantId, Long from, Long to) {
        return scope(tenantId, null, null, null, from, to)
                .toQuery("SELECT type, count() AS cnt FROM " + table,
                        " GROUP BY type ORDER BY cnt DESC");
    }

    /** tenant 격리 하에 [from,to) 안의 목적지 IP 별 건수 집계(world map 용). */
    public ClickHouseQuery geo(String tenant, long from, long to) {
        return TenantScope.of(tenant)
                .add("ts >= {from:UInt64}", "from", String.valueOf(from))
                .add("ts < {to:UInt64}", "to", String.valueOf(to))
                // 네트워크 이벤트가 아닌 행은 dest_ip 가 빈 문자열이라 제외한다.
                .add("dest_ip != ''")
                .toQuery("SELECT dest_ip, count() AS cnt FROM " + table, " GROUP BY dest_ip");
    }

    /** 공통 필터 조립. tenant 로 잠긴 조립기라 어느 경로로 들어와도 조직 격리가 SQL 에 박힌다. */
    private static TenantScope scope(String tenantId, String host, String type, String sha256,
                                     Long from, Long to) {
        TenantScope scope = TenantScope.of(tenantId)
                .addIfText("host = {host:String}", "host", host)
                .addIfText("type = {type:String}", "type", type);
        if (QueryGuards.hasText(sha256)) {
            // 적재 측(collector)이 소문자로 정규화한다. 안 맞추면 대문자 검색어가 같은 파일을 못 찾는다.
            scope.add("sha256 = {sha256:String}", "sha256", sha256.trim().toLowerCase(Locale.ROOT));
        }
        return scope
                .addIfPresent("ts >= {from:UInt64}", "from", from)
                .addIfPresent("ts <= {to:UInt64}", "to", to);
    }

    private static int clampLimit(Integer limit) {
        return QueryGuards.clampLimit(limit, DEFAULT_LIMIT, MAX_LIMIT);
    }
}
