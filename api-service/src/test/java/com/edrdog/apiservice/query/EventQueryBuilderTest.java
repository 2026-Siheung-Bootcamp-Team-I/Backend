package com.edrdog.apiservice.query;

import org.junit.jupiter.api.Test;

import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 조회/요약 SQL 생성과 쿼리 제한(limit 클램프)의 순수 로직 검증.
 * tenant 필터는 멀티테넌시 격리를 위해 항상 들어가며, 모든 필터값은 ClickHouse 파라미터
 * 바인딩({x:Type} + params[x])으로만 들어가야 한다(인젝션 차단).
 */
class EventQueryBuilderTest {

    private final EventQueryBuilder builder = new EventQueryBuilder("edrdog.events");
    private static final String TENANT = "1";
    private static final String HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    // --- limit 클램프 ---

    @Test
    void limit_이_null_이면_기본값_100() {
        ClickHouseQuery q = builder.events(TENANT, null, null, null, null, null, null);
        assertTrue(q.sql().contains("LIMIT 100"), q.sql());
    }

    @Test
    void limit_이_0이하이면_기본값_100() {
        assertTrue(builder.events(TENANT, null, null, null, null, null, 0).sql().contains("LIMIT 100"));
        assertTrue(builder.events(TENANT, null, null, null, null, null, -5).sql().contains("LIMIT 100"));
    }

    @Test
    void limit_이_상한_1000_을_넘으면_1000으로_클램프() {
        ClickHouseQuery q = builder.events(TENANT, null, null, null, null, null, 5000);
        assertTrue(q.sql().contains("LIMIT 1000"), q.sql());
    }

    @Test
    void limit_이_범위_안이면_그대로() {
        ClickHouseQuery q = builder.events(TENANT, null, null, null, null, null, 250);
        assertTrue(q.sql().contains("LIMIT 250"), q.sql());
    }

    // --- 페이지 조회(offset) ---

    @Test
    void 페이지조회는_offset_이_없으면_OFFSET_절을_붙이지_않는다() {
        ClickHouseQuery q = builder.eventsPage(TENANT, null, null, null, null, null, null, null);
        assertFalse(q.sql().contains("OFFSET"), q.sql());
    }

    @Test
    void 페이지조회는_offset_0_도_OFFSET_절을_붙이지_않는다() {
        assertFalse(builder.eventsPage(TENANT, null, null, null, null, null, null, 0).sql().contains("OFFSET"));
    }

    @Test
    void 페이지조회는_offset_을_그대로_건너뛴다() {
        ClickHouseQuery q = builder.eventsPage(TENANT, null, null, null, null, null, 50, 100);
        assertTrue(q.sql().contains("OFFSET 100"), q.sql());
    }

    @Test
    void 페이지조회는_다음페이지_확인용으로_한_행을_더_읽는다() {
        // 다음 페이지가 있는지 알려고 count() 를 한 번 더 도는 것보다 한 행 더 읽는 게 싸다.
        assertTrue(builder.eventsPage(TENANT, null, null, null, null, null, 50, null).sql().contains("LIMIT 51"));
        assertTrue(builder.eventsPage(TENANT, null, null, null, null, null, null, null).sql().contains("LIMIT 101"));
    }

    @Test
    void 페이지조회는_상한_limit_이어도_탐침_행이_사라지지_않는다() {
        // 클램프한 뒤에 +1 이라야 상한(1000)을 요청한 화면도 다음 페이지 유무를 알 수 있다.
        assertTrue(builder.eventsPage(TENANT, null, null, null, null, null, 5000, null).sql().contains("LIMIT 1001"));
    }

    @Test
    void 페이지크기는_limit_클램프_결과와_같다() {
        // 호출부가 탐침 행을 잘라내려면 실제 페이지 크기를 알아야 한다.
        assertEquals(100, EventQueryBuilder.pageSize(null));
        assertEquals(100, EventQueryBuilder.pageSize(0));
        assertEquals(250, EventQueryBuilder.pageSize(250));
        assertEquals(1000, EventQueryBuilder.pageSize(5000));
    }

    @Test
    void offset_이_상한을_넘으면_예외() {
        // 조용히 잘라내면 화면은 데이터가 없다고 읽는다. 명확히 거절해야 한다.
        assertThrows(IllegalArgumentException.class,
                () -> builder.eventsPage(TENANT, null, null, null, null, null, 100, EventQueryBuilder.MAX_OFFSET + 1));
    }

    @Test
    void offset_이_상한과_같으면_통과() {
        ClickHouseQuery q = builder.eventsPage(TENANT, null, null, null, null, null, 100, EventQueryBuilder.MAX_OFFSET);
        assertTrue(q.sql().contains("OFFSET " + EventQueryBuilder.MAX_OFFSET), q.sql());
    }

    @Test
    void offset_이_음수면_예외() {
        assertThrows(IllegalArgumentException.class,
                () -> builder.eventsPage(TENANT, null, null, null, null, null, 100, -1));
    }

    @Test
    void 같은_시간범위를_고정하면_페이지끼리_OFFSET_만_다르다() {
        // 페이지가 겹치거나 빠지지 않으려면 두 요청의 WHERE 가 완전히 같아야 한다.
        ClickHouseQuery p1 = builder.eventsPage(TENANT, "host-01", null, null, 1000L, 2000L, 100, null);
        ClickHouseQuery p2 = builder.eventsPage(TENANT, "host-01", null, null, 1000L, 2000L, 100, 100);
        assertEquals(p1.params(), p2.params());
        assertEquals(p1.sql() + " OFFSET 100", p2.sql());
    }

    @Test
    void 페이지조회도_tenant_격리와_필터를_그대로_건다() {
        ClickHouseQuery q = builder.eventsPage(TENANT, "host-01", "dns", null, 1000L, 2000L, 100, 100);
        assertTrue(q.sql().contains("tenant_id = {tenant:String}"), q.sql());
        assertTrue(q.sql().contains("host = {host:String}"), q.sql());
        assertTrue(q.sql().contains("type = {type:String}"), q.sql());
        assertTrue(q.sql().contains("ORDER BY ts DESC"), q.sql());
        assertEquals(TENANT, q.params().get("tenant"));
    }

    @Test
    void 페이지조회도_tenant_가_없으면_예외() {
        assertThrows(IllegalArgumentException.class,
                () -> builder.eventsPage(null, null, null, null, null, null, 100, 0));
    }

    // --- 총 건수 ---

    @Test
    void 총건수는_같은_WHERE_로_센다() {
        ClickHouseQuery page = builder.eventsPage(TENANT, "host-01", "dns", HASH, 1000L, 2000L, 100, 100);
        ClickHouseQuery count = builder.countEvents(TENANT, "host-01", "dns", HASH, 1000L, 2000L);
        assertTrue(count.sql().contains("count() AS cnt"), count.sql());
        assertEquals(page.params(), count.params());
    }

    @Test
    void 총건수는_tenant_밖을_세지_않는다() {
        ClickHouseQuery q = builder.countEvents(TENANT, null, null, null, null, null);
        assertTrue(q.sql().contains("tenant_id = {tenant:String}"), q.sql());
        assertEquals(TENANT, q.params().get("tenant"));
    }

    @Test
    void 총건수도_tenant_가_없으면_예외() {
        assertThrows(IllegalArgumentException.class,
                () -> builder.countEvents(null, null, null, null, null, null));
        assertThrows(IllegalArgumentException.class,
                () -> builder.countEvents("  ", null, null, null, null, null));
    }

    @Test
    void 총건수는_LIMIT_이나_정렬을_붙이지_않는다() {
        // 전체를 세는 쿼리라 정렬/상한이 붙으면 의미가 달라진다.
        ClickHouseQuery q = builder.countEvents(TENANT, null, null, null, null, null);
        assertFalse(q.sql().contains("LIMIT"), q.sql());
        assertFalse(q.sql().contains("ORDER BY"), q.sql());
    }

    // --- tenant 필수 격리 ---

    @Test
    void tenant_는_항상_WHERE_에_바인딩된다() {
        ClickHouseQuery q = builder.events(TENANT, null, null, null, null, null, 100);
        assertTrue(q.sql().contains("WHERE"), q.sql());
        assertTrue(q.sql().contains("tenant_id = {tenant:String}"), q.sql());
        assertEquals(TENANT, q.params().get("tenant"));
    }

    @Test
    void 다른_필터가_없으면_tenant_만_바인딩된다() {
        ClickHouseQuery q = builder.events(TENANT, null, null, null, null, null, 100);
        assertEquals(1, q.params().size());
        assertEquals(TENANT, q.params().get("tenant"));
    }

    @Test
    void tenant_값은_SQL_본문에_직접_박히지_않는다() {
        ClickHouseQuery q = builder.events("1 OR 1=1", null, null, null, null, null, 100);
        assertFalse(q.sql().contains("1 OR 1=1"), q.sql());
        assertEquals("1 OR 1=1", q.params().get("tenant"));
    }

    @Test
    void tenant_가_null_이거나_빈값이면_예외() {
        assertThrows(IllegalArgumentException.class,
                () -> builder.events(null, null, null, null, null, null, 100));
        assertThrows(IllegalArgumentException.class,
                () -> builder.events("  ", null, null, null, null, null, 100));
        assertThrows(IllegalArgumentException.class,
                () -> builder.summaryByType(null, null, null));
    }

    // --- WHERE / 파라미터 바인딩 ---

    @Test
    void host_필터는_파라미터_바인딩으로_들어간다() {
        ClickHouseQuery q = builder.events(TENANT, "host-01", null, null, null, null, 100);
        assertTrue(q.sql().contains("host = {host:String}"), q.sql());
        assertEquals("host-01", q.params().get("host"));
        assertEquals(TENANT, q.params().get("tenant"));
        // 값은 SQL 본문에 직접 박히지 않는다
        assertFalse(q.sql().contains("host-01"), q.sql());
    }

    @Test
    void type_필터_바인딩() {
        ClickHouseQuery q = builder.events(TENANT, null, "process", null, null, null, 100);
        assertTrue(q.sql().contains("type = {type:String}"), q.sql());
        assertEquals("process", q.params().get("type"));
    }

    @Test
    void dns_l7_도_type_필터로_쓸_수_있다() {
        // 타입 화이트리스트를 두지 않고 값을 그대로 바인딩하므로 새 타입이 늘어도 조회가 막히지 않는다.
        assertEquals("dns", builder.events(TENANT, null, "dns", null, null, null, 100).params().get("type"));
        assertEquals("l7", builder.events(TENANT, null, "l7", null, null, null, 100).params().get("type"));
    }

    @Test
    void 조회_컬럼에_domain_과_detail_이_들어간다() {
        // 대시보드가 dns/l7 이벤트의 도메인과 부가정보를 보려면 조회 결과에 실려야 한다.
        ClickHouseQuery q = builder.events(TENANT, null, null, null, null, null, 100);
        assertTrue(q.sql().contains("domain"), q.sql());
        assertTrue(q.sql().contains("detail"), q.sql());
    }

    @Test
    void 조회_컬럼에_sha256_이_들어간다() {
        // 어떤 파일이 걸린 건지 화면에서 확인하려면 조회 결과에 해시가 실려야 한다.
        ClickHouseQuery q = builder.events(TENANT, null, null, null, null, null, 100);
        assertTrue(q.sql().contains("sha256"), q.sql());
    }

    @Test
    void sha256_필터는_파라미터_바인딩으로_들어간다() {
        // "이 악성코드 해시가 우리 조직 어딘가에 있었나" 를 묻는 조회.
        ClickHouseQuery q = builder.events(TENANT, null, null, HASH, null, null, 100);
        assertTrue(q.sql().contains("sha256 = {sha256:String}"), q.sql());
        assertEquals(HASH, q.params().get("sha256"));
        assertFalse(q.sql().contains(HASH), q.sql());
    }

    @Test
    void sha256_필터는_대문자로_들어와도_소문자로_찾는다() {
        // 적재되는 값은 소문자로 정규화돼 있다. 검색어 대소문자 때문에 조회가 갈리면 안 된다.
        ClickHouseQuery q = builder.events(TENANT, null, null, HASH.toUpperCase(Locale.ROOT), null, null, 100);
        assertEquals(HASH, q.params().get("sha256"));
    }

    @Test
    void 빈문자열_sha256_은_필터로_치지_않는다() {
        ClickHouseQuery q = builder.events(TENANT, null, null, "   ", null, null, 100);
        assertEquals(1, q.params().size());
        assertFalse(q.sql().contains("sha256 = "), q.sql());
    }

    @Test
    void 시간범위_from_to_는_ts_에_바인딩() {
        ClickHouseQuery q = builder.events(TENANT, null, null, null, 1000L, 2000L, 100);
        assertTrue(q.sql().contains("ts >= {from:UInt64}"), q.sql());
        assertTrue(q.sql().contains("ts <= {to:UInt64}"), q.sql());
        assertEquals("1000", q.params().get("from"));
        assertEquals("2000", q.params().get("to"));
    }

    @Test
    void 여러_필터는_AND_로_결합_되고_tenant_도_함께_바인딩() {
        ClickHouseQuery q = builder.events(TENANT, "host-01", "network", null, null, null, 100);
        assertTrue(q.sql().contains(" AND "), q.sql());
        // tenant + host + type
        assertEquals(3, q.params().size());
        assertEquals(TENANT, q.params().get("tenant"));
    }

    @Test
    void 빈문자열_host_type_은_무시되고_tenant_만_남는다() {
        ClickHouseQuery q = builder.events(TENANT, "  ", "", null, null, null, 100);
        assertEquals(1, q.params().size());
        assertTrue(q.sql().contains("tenant_id = {tenant:String}"), q.sql());
    }

    @Test
    void 최신순_정렬() {
        assertTrue(builder.events(TENANT, null, null, null, null, null, 100).sql().contains("ORDER BY ts DESC"));
    }

    // --- lineage ---

    @Test
    void lineage는_tenant_host_시간윈도우를_모두_바인딩한다() {
        ClickHouseQuery q = builder.lineageEvents(TENANT, "host-01", 1000L, 2000L);
        assertTrue(q.sql().contains("tenant_id = {tenant:String}"), q.sql());
        assertTrue(q.sql().contains("host = {host:String}"), q.sql());
        assertTrue(q.sql().contains("ts >= {from:UInt64}"), q.sql());
        assertTrue(q.sql().contains("ts <= {to:UInt64}"), q.sql());
        assertEquals(TENANT, q.params().get("tenant"));
        assertEquals("host-01", q.params().get("host"));
        assertEquals("1000", q.params().get("from"));
        assertEquals("2000", q.params().get("to"));
    }

    @Test
    void lineage는_그래프_빌드에_필요한_컬럼만_시간순으로_뽑는다() {
        ClickHouseQuery q = builder.lineageEvents(TENANT, "host-01", 1000L, 2000L);
        assertTrue(q.sql().contains("process"), q.sql());
        assertTrue(q.sql().contains("parent"), q.sql());
        assertTrue(q.sql().contains("dest_ip"), q.sql());
        assertTrue(q.sql().contains("dest_port"), q.sql());
        assertTrue(q.sql().contains("ORDER BY ts ASC"), q.sql());
    }

    // detail 은 pid/ppid 가 든 칸이다. 지금 계보 빌더는 pid/ppid 를 못 써서 동명 프로세스를
    // 한 노드로 합치는데, 이 컬럼이 열려 있어야 나중에 pid 기반으로 정확히 나눌 수 있다.
    @Test
    void lineage_는_pid_ppid_가_든_detail_도_뽑는다() {
        ClickHouseQuery q = builder.lineageEvents(TENANT, "host-01", 1000L, 2000L);
        assertTrue(q.sql().contains("detail"), q.sql());
    }

    @Test
    void lineage도_상한으로_클램프해_폭주를_막는다() {
        ClickHouseQuery q = builder.lineageEvents(TENANT, "host-01", 1000L, 2000L);
        assertTrue(q.sql().contains("LIMIT 1000"), q.sql());
    }

    @Test
    void lineage도_tenant_가_null_이면_예외() {
        assertThrows(IllegalArgumentException.class,
                () -> builder.lineageEvents(null, "host-01", 1000L, 2000L));
    }

    // --- 단건(id) 조회용 좁은 창 ---

    @Test
    void 단건조회는_tenant_host_와_ts_주변_창을_바인딩한다() {
        ClickHouseQuery q = builder.eventAt(TENANT, "host-01", 10_000L);
        assertTrue(q.sql().contains("tenant_id = {tenant:String}"), q.sql());
        assertTrue(q.sql().contains("host = {host:String}"), q.sql());
        assertTrue(q.sql().contains("ts >= {from:UInt64}"), q.sql());
        assertTrue(q.sql().contains("ts <= {to:UInt64}"), q.sql());
        assertEquals(TENANT, q.params().get("tenant"));
        assertEquals("host-01", q.params().get("host"));
    }

    @Test
    void 단건조회_창은_ts_를_가운데_둔_반폭만큼이다() {
        ClickHouseQuery q = builder.eventAt(TENANT, "host-01", 10_000L);
        assertEquals(String.valueOf(10_000L - EventQueryBuilder.POINT_WINDOW_MS), q.params().get("from"));
        assertEquals(String.valueOf(10_000L + EventQueryBuilder.POINT_WINDOW_MS), q.params().get("to"));
    }

    @Test
    void 단건조회_창의_시작은_음수로_내려가지_않는다() {
        // ts 가 창 반폭보다 작으면 from 이 음수가 되는데, ClickHouse UInt64 바인딩이 깨진다.
        ClickHouseQuery q = builder.eventAt(TENANT, "host-01", 10L);
        assertEquals("0", q.params().get("from"));
    }

    @Test
    void 단건조회는_id_를_다시_접을_수_있는_컬럼을_모두_뽑는다() {
        // id 는 저장돼 있지 않고 행에서 다시 계산한다. 씨앗 컬럼이 하나라도 빠지면 영영 일치하지 않는다.
        ClickHouseQuery q = builder.eventAt(TENANT, "host-01", 10_000L);
        assertTrue(q.sql().contains("host"), q.sql());
        assertTrue(q.sql().contains("type"), q.sql());
        assertTrue(q.sql().contains("process"), q.sql());
        assertTrue(q.sql().contains("parent"), q.sql());
        assertTrue(q.sql().contains("dest_ip"), q.sql());
        assertTrue(q.sql().contains("dest_port"), q.sql());
        assertTrue(q.sql().contains("detail"), q.sql());
    }

    @Test
    void 단건조회도_상한으로_클램프한다() {
        // 바쁜 호스트는 창 안에서도 행이 쏟아진다. 기본 100 이면 찾는 행이 잘려 나가 404 가 된다.
        assertTrue(builder.eventAt(TENANT, "host-01", 10_000L).sql().contains("LIMIT 1000"));
    }

    @Test
    void 단건조회는_tenant_가_없으면_예외() {
        assertThrows(IllegalArgumentException.class, () -> builder.eventAt(null, "host-01", 10_000L));
        assertThrows(IllegalArgumentException.class, () -> builder.eventAt("  ", "host-01", 10_000L));
    }

    @Test
    void 단건조회는_host_가_없으면_예외() {
        // host 가 빠지면 창 조건만 남아 tenant 전체를 훑는다. 그 비용을 지려고 만든 경로가 아니다.
        assertThrows(IllegalArgumentException.class, () -> builder.eventAt(TENANT, null, 10_000L));
        assertThrows(IllegalArgumentException.class, () -> builder.eventAt(TENANT, "  ", 10_000L));
    }

    @Test
    void 단건조회_host_값은_SQL_본문에_직접_박히지_않는다() {
        ClickHouseQuery q = builder.eventAt(TENANT, "host-01' OR 1=1", 10_000L);
        assertFalse(q.sql().contains("OR 1=1"), q.sql());
        assertEquals("host-01' OR 1=1", q.params().get("host"));
    }

    // --- 요약 ---

    @Test
    void 요약은_tenant_로_필터하며_type별_집계_쿼리를_만든다() {
        ClickHouseQuery q = builder.summaryByType(TENANT, null, null);
        assertTrue(q.sql().contains("tenant_id = {tenant:String}"), q.sql());
        assertEquals(TENANT, q.params().get("tenant"));
        assertTrue(q.sql().contains("GROUP BY type"), q.sql());
        assertTrue(q.sql().contains("count()"), q.sql());
    }

    @Test
    void 요약도_시간범위_바인딩을_지원() {
        ClickHouseQuery q = builder.summaryByType(TENANT, 1000L, 2000L);
        assertTrue(q.sql().contains("ts >= {from:UInt64}"), q.sql());
        assertEquals("1000", q.params().get("from"));
        assertEquals("2000", q.params().get("to"));
    }

    // --- 호스트 목록 ---

    @Test
    void 호스트목록은_tenant로_필터하며_host별_last_seen을_집계한다() {
        ClickHouseQuery q = builder.hostsLastSeen(TENANT);
        assertTrue(q.sql().contains("tenant_id = {tenant:String}"), q.sql());
        assertEquals(TENANT, q.params().get("tenant"));
        assertTrue(q.sql().contains("max(ts) AS last_seen"), q.sql());
        assertTrue(q.sql().contains("GROUP BY host"), q.sql());
    }

    @Test
    void 호스트목록은_last_seen_최신순() {
        assertTrue(builder.hostsLastSeen(TENANT).sql().contains("ORDER BY last_seen DESC"));
    }

    @Test
    void 호스트목록도_tenant_필수() {
        assertThrows(IllegalArgumentException.class, () -> builder.hostsLastSeen(null));
        assertThrows(IllegalArgumentException.class, () -> builder.hostsLastSeen("  "));
    }
}
