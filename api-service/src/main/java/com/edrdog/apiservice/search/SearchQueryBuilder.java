package com.edrdog.apiservice.search;

import com.edrdog.apiservice.query.ClickHouseQuery;
import com.edrdog.apiservice.query.QueryGuards;
import com.edrdog.apiservice.query.TenantScope;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * 상단바 통합 검색의 events/alerts 조회 SQL 을 만드는 순수 로직
 * (EventQueryBuilder·AlertQueryBuilder 와 같은 패턴: tenant 강제 + 파라미터 바인딩 + 상한 클램프).
 *
 * <p><b>LIKE 로 바꾸면 needle 의 %/_ 가 패턴이 되어 검색 한 번이 전체를 긁는다.</b> positionCaseInsensitive 는
 * needle 을 글자로만 보므로 이스케이프 자체가 필요 없고, 대소문자 무관도 같은 함수가 해결한다.
 * <p>부분일치는 인덱스를 못 쓴다. 비용은 호출부가 좁혀 주는 시간 범위와 건수 상한으로만 묶인다.
 */
@Component
public class SearchQueryBuilder {

    /** 상단바 드롭다운은 종류별로 몇 줄만 보여 준다. 더 필요하면 각 목록 조회로 넘어가는 자리다. */
    public static final int DEFAULT_LIMIT = 5;

    /** 상한. 드롭다운이 감당하는 줄 수의 끝이고, 여기가 스캔 결과를 실어 나르는 비용의 상한이다. */
    public static final int MAX_LIMIT = 20;

    /**
     * 이벤트에서 훑을 컬럼. 조사하는 사람이 상단바에 칠 법한 것만 골랐다.
     * type 을 넣으면 부분일치로 그 종류 전체가 딸려 나오고, detail 은 JSON 원문이라 스캔 비용이 가장 많이 붙는다.
     */
    private static final List<String> EVENT_FIELDS =
            List.of("host", "process", "parent", "cmdline", "domain", "dest_ip", "sha256");

    /**
     * 알림에서 훑을 컬럼. id 는 티켓·공유 링크에서 복사해 붙이는 경로가 실제로 있어 넣고, mitre 는 T1059 같은 태그로 찾는다.
     * matched(Array)는 룰이 무엇에 걸렸는지의 내부 표현이라 사람이 칠 말이 아니라서 뺐다.
     */
    private static final List<String> ALERT_FIELDS =
            List.of("id", "host", "rule_id", "mitre", "domain", "dest_ip");

    /**
     * 이벤트 조회 컬럼. id 는 저장된 값이 아니라 이 컬럼들을 접어 만들므로(EventId)
     * 하나라도 빼면 검색 결과에서 이벤트 단건으로 넘어갈 수 없다.
     */
    private static final String EVENT_COLUMNS =
            "host, type, ts, process, parent, cmdline, dest_ip, dest_port, domain, detail, sha256";

    private static final String ALERT_COLUMNS =
            "id, host, rule_id, mitre, severity, ts";

    private final String eventsTable;
    private final String alertsTable;

    public SearchQueryBuilder(@Value("${edrdog.clickhouse.table}") String eventsTable,
                              @Value("${edrdog.clickhouse.alerts-table}") String alertsTable) {
        this.eventsTable = eventsTable;
        this.alertsTable = alertsTable;
    }

    /** tenant 격리 하에 시간 범위[from,to] 안의 events 를 질의어 부분일치로 훑는다. tenantId·term 은 필수. */
    public ClickHouseQuery events(String tenantId, String term, long from, long to, Integer limit) {
        return scope(tenantId, term, from, to, EVENT_FIELDS, List.of())
                .toQuery("SELECT " + EVENT_COLUMNS + " FROM " + eventsTable,
                        " ORDER BY ts DESC LIMIT " + (pageSize(limit) + 1));
    }

    /**
     * tenant 격리 하에 시간 범위[from,to] 안의 alerts 를 질의어 부분일치로 훑는다.
     * ruleIds 는 한글 위협명으로 미리 찾아 둔 룰(SearchService.threatRuleIds)이며, 질의어 조건에 OR 로 얹는다.
     * FINAL 을 빼면 ReplacingMergeTree dedup 전 행이 섞여 같은 알림이 여러 줄로 나온다.
     */
    public ClickHouseQuery alerts(String tenantId, String term, List<String> ruleIds,
                                  long from, long to, Integer limit) {
        return scope(tenantId, term, from, to, ALERT_FIELDS, ruleIds)
                .toQuery("SELECT " + ALERT_COLUMNS + " FROM " + alertsTable + " FINAL",
                        " ORDER BY ts DESC LIMIT " + (pageSize(limit) + 1));
    }

    /** 클램프가 적용된 실제 섹션 크기. 호출부가 탐침 행을 잘라내려면 이 값을 알아야 한다. */
    public static int pageSize(Integer limit) {
        return QueryGuards.clampLimit(limit, DEFAULT_LIMIT, MAX_LIMIT);
    }

    private static TenantScope scope(String tenantId, String term, long from, long to,
                                     List<String> fields, List<String> ruleIds) {
        TenantScope scope = TenantScope.of(tenantId);
        if (!QueryGuards.hasText(term)) {
            throw new IllegalArgumentException("검색어는 필수입니다");
        }
        scope.add("ts >= {from:UInt64}", "from", String.valueOf(from))
                .add("ts <= {to:UInt64}", "to", String.valueOf(to));
        return scope.add("(" + String.join(" OR ", matchConds(term, fields, ruleIds, scope)) + ")");
    }

    /** 훑을 컬럼 하나당 조건 하나. 질의어와 ruleId 는 전부 바인딩이라 SQL 에 문자열이 들어가지 않는다. */
    private static List<String> matchConds(String term, List<String> fields, List<String> ruleIds,
                                           TenantScope scope) {
        scope.bind("q", term);
        List<String> conds = new ArrayList<>();
        for (String field : fields) {
            conds.add("positionCaseInsensitive(" + field + ", {q:String}) > 0");
        }
        for (int i = 0; i < ruleIds.size(); i++) {
            String name = "rid" + i;
            conds.add("rule_id = {" + name + ":String}");
            scope.bind(name, ruleIds.get(i));
        }
        return conds;
    }
}
