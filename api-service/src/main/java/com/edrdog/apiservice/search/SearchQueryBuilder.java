package com.edrdog.apiservice.search;

import com.edrdog.apiservice.query.ClickHouseQuery;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 상단바 통합 검색의 events/alerts 조회 SQL 을 만드는 순수 로직
 * (EventQueryBuilder·AlertQueryBuilder 와 같은 패턴: tenant 강제 + 파라미터 바인딩 + 상한 클램프).
 *
 * <p><b>LIKE 대신 positionCaseInsensitive 를 쓰는 이유.</b> LIKE 는 needle 의 %/_ 를 패턴으로 읽는다.
 * 상단바에 %를 친 사람은 그 글자를 찾는 것인데 LIKE 로는 그게 "전부" 라는 뜻이 되어, 검색 한 번이
 * 전체를 긁어 상위 N건을 무작위로 돌려준다. 이스케이프로 막을 수도 있지만 position 계열은 needle 을
 * 애초에 글자로만 보므로 이스케이프 자체가 필요 없다. 대소문자 무관도 같은 함수가 해결한다
 * (도메인·해시가 소문자로 적재되어 있어도 대문자로 친 검색어가 그대로 걸린다).
 *
 * <p><b>부분일치는 인덱스를 못 쓴다.</b> 그래서 이 조회의 비용은 스캔 범위로만 묶인다:
 * 호출부가 항상 시간 범위를 좁혀 주고, 뽑는 건수는 상한으로 클램프한다.
 */
@Component
public class SearchQueryBuilder {

    /** 상단바 드롭다운은 종류별로 몇 줄만 보여 준다. 더 필요하면 각 목록 조회로 넘어가는 자리다. */
    public static final int DEFAULT_LIMIT = 5;

    /** 상한. 드롭다운이 감당하는 줄 수의 끝이고, 여기가 스캔 결과를 실어 나르는 비용의 상한이다. */
    public static final int MAX_LIMIT = 20;

    /**
     * 이벤트에서 훑을 컬럼. 조사하는 사람이 상단바에 칠 법한 것만 골랐다:
     * 기기 이름(host), 프로세스와 그 부모(process/parent), 명령줄(cmdline), 목적지(domain/dest_ip), 파일 해시(sha256).
     *
     * <p>제외한 것들. type 은 값이 몇 종류뿐이라 부분일치로 치면 그 종류 전체가 딸려 나온다(그건 필터가 할 일이다).
     * detail 은 JSON 원문이라 이 표에서 가장 크고, 훑으면 스캔 비용이 가장 많이 붙는 컬럼인데
     * 그 안의 값은 대부분 이미 다른 컬럼에 펴져 있다.
     */
    private static final List<String> EVENT_FIELDS =
            List.of("host", "process", "parent", "cmdline", "domain", "dest_ip", "sha256");

    /**
     * 알림에서 훑을 컬럼. id 를 넣는 이유는 티켓이나 공유 링크에서 알림 id 를 복사해 상단바에 붙이는
     * 경로가 실제로 있어서다. mitre 는 조사자가 T1059 같은 태그로 찾는다.
     * matched(Array)는 룰이 무엇에 걸렸는지의 내부 표현이라 사람이 칠 말이 아니라서 뺐다.
     */
    private static final List<String> ALERT_FIELDS =
            List.of("id", "host", "rule_id", "mitre", "domain", "dest_ip");

    /**
     * 이벤트 조회 컬럼. 화면에 보일 값(process/cmdline/domain)에 더해, 검색 결과에서 이벤트 단건으로
     * 바로 넘어가는 데 필요한 씨앗(host/ts/type/process/parent/dest_ip/dest_port/detail 의 pid)이 전부 있어야 한다.
     * id 는 저장된 값이 아니라 이 컬럼들을 접어 만들기 때문이다(EventId).
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
        Map<String, String> params = new LinkedHashMap<>();
        String where = where(tenantId, term, from, to, EVENT_FIELDS, List.of(), params);
        String sql = "SELECT " + EVENT_COLUMNS + " FROM " + eventsTable
                + where
                + " ORDER BY ts DESC LIMIT " + (pageSize(limit) + 1);
        return new ClickHouseQuery(sql, params);
    }

    /**
     * tenant 격리 하에 시간 범위[from,to] 안의 alerts 를 질의어 부분일치로 훑는다.
     * ruleIds 는 한글 위협명으로 미리 찾아 둔 룰(SearchService.threatRuleIds)이며, 질의어 조건에 OR 로 얹는다.
     * ReplacingMergeTree dedup 때문에 FROM ... FINAL 을 쓴다(AlertQueryBuilder 와 같은 이유).
     */
    public ClickHouseQuery alerts(String tenantId, String term, List<String> ruleIds,
                                  long from, long to, Integer limit) {
        Map<String, String> params = new LinkedHashMap<>();
        String where = where(tenantId, term, from, to, ALERT_FIELDS, ruleIds, params);
        String sql = "SELECT " + ALERT_COLUMNS + " FROM " + alertsTable + " FINAL"
                + where
                + " ORDER BY ts DESC LIMIT " + (pageSize(limit) + 1);
        return new ClickHouseQuery(sql, params);
    }

    /** 클램프가 적용된 실제 섹션 크기. 호출부가 탐침 행을 잘라내려면 이 값을 알아야 한다. */
    public static int pageSize(Integer limit) {
        if (limit == null || limit <= 0) {
            return DEFAULT_LIMIT;
        }
        return Math.min(limit, MAX_LIMIT);
    }

    private static String where(String tenantId, String term, long from, long to,
                                List<String> fields, List<String> ruleIds, Map<String, String> params) {
        if (!hasText(tenantId)) {
            throw new IllegalArgumentException("tenant 는 필수입니다(격리)");
        }
        if (!hasText(term)) {
            throw new IllegalArgumentException("검색어는 필수입니다");
        }
        List<String> conds = new ArrayList<>();
        // tenant 격리는 항상 첫 조건으로 강제한다.
        conds.add("tenant_id = {tenant:String}");
        params.put("tenant", tenantId.trim());
        conds.add("ts >= {from:UInt64}");
        params.put("from", String.valueOf(from));
        conds.add("ts <= {to:UInt64}");
        params.put("to", String.valueOf(to));
        conds.add("(" + String.join(" OR ", matchConds(term, fields, ruleIds, params)) + ")");
        return " WHERE " + String.join(" AND ", conds);
    }

    /** 훑을 컬럼 하나당 조건 하나. 질의어와 ruleId 는 전부 바인딩이라 SQL 에 문자열이 들어가지 않는다. */
    private static List<String> matchConds(String term, List<String> fields, List<String> ruleIds,
                                           Map<String, String> params) {
        params.put("q", term);
        List<String> conds = new ArrayList<>();
        for (String field : fields) {
            conds.add("positionCaseInsensitive(" + field + ", {q:String}) > 0");
        }
        for (int i = 0; i < ruleIds.size(); i++) {
            String name = "rid" + i;
            conds.add("rule_id = {" + name + ":String}");
            params.put(name, ruleIds.get(i));
        }
        return conds;
    }

    private static boolean hasText(String s) {
        return s != null && !s.trim().isEmpty();
    }
}
