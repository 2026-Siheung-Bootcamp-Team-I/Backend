package com.edrdog.apiservice.search;

import com.edrdog.apiservice.query.ClickHouseQuery;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 통합 검색 SQL 생성(순수) 검증. tenant 격리 강제, 질의어의 파라미터 바인딩, 시간 범위와
 * 건수 상한이 이 기능의 안전장치라 전부 여기서 고정한다.
 */
class SearchQueryBuilderTest {

    private final SearchQueryBuilder builder = new SearchQueryBuilder("edrdog.events", "edrdog.alerts");
    private static final String TENANT = "1";
    private static final long FROM = 1_000L;
    private static final long TO = 2_000L;

    // --- tenant 격리 ---

    @Test
    void tenant_가_없으면_예외() {
        assertThrows(IllegalArgumentException.class,
                () -> builder.events(null, "gimdong", FROM, TO, null));
        assertThrows(IllegalArgumentException.class,
                () -> builder.events("  ", "gimdong", FROM, TO, null));
        assertThrows(IllegalArgumentException.class,
                () -> builder.alerts(null, "gimdong", List.of(), FROM, TO, null));
    }

    @Test
    void tenant_조건이_항상_들어간다() {
        ClickHouseQuery events = builder.events(TENANT, "gimdong", FROM, TO, null);
        assertTrue(events.sql().contains("tenant_id = {tenant:String}"), events.sql());
        assertEquals(TENANT, events.params().get("tenant"));

        ClickHouseQuery alerts = builder.alerts(TENANT, "gimdong", List.of(), FROM, TO, null);
        assertTrue(alerts.sql().contains("tenant_id = {tenant:String}"), alerts.sql());
        assertEquals(TENANT, alerts.params().get("tenant"));
    }

    // --- 질의어 바인딩 ---

    @Test
    void 질의어가_없으면_예외() {
        assertThrows(IllegalArgumentException.class, () -> builder.events(TENANT, "  ", FROM, TO, null));
        assertThrows(IllegalArgumentException.class, () -> builder.alerts(TENANT, null, List.of(), FROM, TO, null));
    }

    @Test
    void 질의어는_SQL_에_이어붙지_않고_파라미터로만_들어간다() {
        ClickHouseQuery q = builder.events(TENANT, "gimdong", FROM, TO, null);
        assertFalse(q.sql().contains("gimdong"), q.sql());
        assertEquals("gimdong", q.params().get("q"));
    }

    @Test
    void 인젝션_시도_문자열도_파라미터로만_들어간다() {
        String attack = "'; DROP TABLE edrdog.events; --";
        ClickHouseQuery q = builder.events(TENANT, attack, FROM, TO, null);
        assertFalse(q.sql().contains("DROP TABLE"), q.sql());
        assertEquals(attack, q.params().get("q"));
    }

    @Test
    void 와일드카드_문자는_LIKE_패턴이_아니라_찾을_글자로_들어간다() {
        // LIKE 를 쓰면 q=% 한 번이 전체 스캔 + 전체 결과가 된다. position 계열은 needle 을 글자로만 본다.
        ClickHouseQuery q = builder.events(TENANT, "%", FROM, TO, null);
        assertFalse(q.sql().contains("LIKE"), q.sql());
        assertEquals("%", q.params().get("q"));
    }

    @Test
    void 대소문자를_가리지_않는_비교를_쓴다() {
        String sql = builder.events(TENANT, "GIMDONG", FROM, TO, null).sql();
        assertTrue(sql.contains("positionCaseInsensitive("), sql);
    }

    // --- 검색 대상 컬럼 ---

    @Test
    void 이벤트는_호스트_프로세스_명령줄_도메인_목적지IP_해시를_훑는다() {
        String sql = builder.events(TENANT, "gimdong", FROM, TO, null).sql();
        for (String field : List.of("host", "process", "parent", "cmdline", "domain", "dest_ip", "sha256")) {
            assertTrue(sql.contains("positionCaseInsensitive(" + field + ", {q:String}) > 0"), field + " / " + sql);
        }
    }

    @Test
    void 알림은_호스트_룰_MITRE_도메인_목적지IP_id_를_훑는다() {
        String sql = builder.alerts(TENANT, "gimdong", List.of(), FROM, TO, null).sql();
        for (String field : List.of("id", "host", "rule_id", "mitre", "domain", "dest_ip")) {
            assertTrue(sql.contains("positionCaseInsensitive(" + field + ", {q:String}) > 0"), field + " / " + sql);
        }
    }

    @Test
    void 이벤트_조회는_단건_링크에_필요한_컬럼을_다_뽑는다() {
        // id 는 저장된 값이 아니라 행 내용을 접어 만든다(EventId). 씨앗 컬럼이 빠지면 링크가 조용히 안 열린다.
        String sql = builder.events(TENANT, "gimdong", FROM, TO, null).sql();
        for (String col : List.of("host", "type", "ts", "process", "parent", "dest_ip", "dest_port", "detail")) {
            assertTrue(sql.contains(col), col + " / " + sql);
        }
    }

    @Test
    void 알림은_중복제거를_위해_FINAL_로_읽는다() {
        assertTrue(builder.alerts(TENANT, "gimdong", List.of(), FROM, TO, null).sql().contains("FINAL"));
    }

    // --- 한글 위협명으로 찾은 ruleId ---

    @Test
    void 위협명으로_찾은_ruleId_는_바인딩된_동등비교로_붙는다() {
        ClickHouseQuery q = builder.alerts(TENANT, "다운로드", List.of("DOWNLOAD_AND_EXECUTE"), FROM, TO, null);
        assertTrue(q.sql().contains("rule_id = {rid0:String}"), q.sql());
        assertFalse(q.sql().contains("DOWNLOAD_AND_EXECUTE"), q.sql());
        assertEquals("DOWNLOAD_AND_EXECUTE", q.params().get("rid0"));
    }

    @Test
    void 위협명에_걸린_ruleId_가_없으면_그_조건은_안_붙는다() {
        assertFalse(builder.alerts(TENANT, "gimdong", List.of(), FROM, TO, null).sql().contains("rid0"));
    }

    // --- 시간 범위 ---

    @Test
    void 시간_범위가_항상_걸린다() {
        ClickHouseQuery q = builder.events(TENANT, "gimdong", FROM, TO, null);
        assertTrue(q.sql().contains("ts >= {from:UInt64}"), q.sql());
        assertTrue(q.sql().contains("ts <= {to:UInt64}"), q.sql());
        assertEquals("1000", q.params().get("from"));
        assertEquals("2000", q.params().get("to"));
    }

    // --- 건수 상한 ---

    @Test
    void limit_이_null_이면_기본값을_쓴다() {
        assertEquals(SearchQueryBuilder.DEFAULT_LIMIT, SearchQueryBuilder.pageSize(null));
    }

    @Test
    void limit_이_0이하이면_기본값을_쓴다() {
        assertEquals(SearchQueryBuilder.DEFAULT_LIMIT, SearchQueryBuilder.pageSize(0));
        assertEquals(SearchQueryBuilder.DEFAULT_LIMIT, SearchQueryBuilder.pageSize(-3));
    }

    @Test
    void limit_이_상한을_넘으면_클램프한다() {
        assertEquals(SearchQueryBuilder.MAX_LIMIT, SearchQueryBuilder.pageSize(1000));
    }

    @Test
    void 잘렸는지_알려고_한_행을_더_읽는다() {
        // count() 를 한 번 더 도는 것보다 탐침 한 행이 싸다(다른 목록 조회와 같은 방식).
        assertTrue(builder.events(TENANT, "gimdong", FROM, TO, 3).sql().endsWith("LIMIT 4"),
                builder.events(TENANT, "gimdong", FROM, TO, 3).sql());
        assertTrue(builder.alerts(TENANT, "gimdong", List.of(), FROM, TO, 3).sql().endsWith("LIMIT 4"));
    }

    @Test
    void 최신순으로_정렬한다() {
        assertTrue(builder.events(TENANT, "gimdong", FROM, TO, null).sql().contains("ORDER BY ts DESC"));
        assertTrue(builder.alerts(TENANT, "gimdong", List.of(), FROM, TO, null).sql().contains("ORDER BY ts DESC"));
    }
}
