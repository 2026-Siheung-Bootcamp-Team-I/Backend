package com.edrdog.apiservice.search;

import com.edrdog.apiservice.clickhouse.ClickHouseReader;
import com.edrdog.apiservice.query.ClickHouseQuery;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * GET /api/search 배선 검증. 상단바가 한 번에 알림·호스트·이벤트를 훑는 경로다.
 *
 * <p>ClickHouse 는 목으로 대체하되 tenant·시간창·부분일치를 흉내 낸다. 격리와 일치 규칙이 이 기능의
 * 핵심이라, 목이 그것을 무시하면 검증이 성립하지 않는다(EventLookupApiIntegrationTest 와 같은 방식).
 * 목이 훑는 컬럼 목록은 SearchQueryBuilder 의 것과 같아야 한다.
 *
 * <p>/api/search 는 아직 ApiKeyPolicy 예외가 아니라 X-API-Key 가 필요하다(기본 키 dev-api-key).
 * 예외로 열려도 키를 같이 보내는 건 그대로 통과하므로 이 테스트는 어느 쪽이든 성립한다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.ANY)
@TestPropertySource(properties = "spring.kafka.listener.auto-startup=false")
class SearchApiIntegrationTest {

    private static final String API_KEY = "dev-api-key";
    private static final String MAC = "gimdonghyeon-ui-MacBookPro.local";

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper om;

    @MockitoBean
    private ClickHouseReader reader;

    private final List<Map<String, Object>> eventRows = new ArrayList<>();
    private final List<Map<String, Object>> alertRows = new ArrayList<>();

    /** SearchQueryBuilder 가 훑는 이벤트 컬럼. */
    private static final List<String> EVENT_FIELDS =
            List.of("host", "process", "parent", "cmdline", "domain", "dest_ip", "sha256");

    /** SearchQueryBuilder 가 훑는 알림 컬럼. */
    private static final List<String> ALERT_FIELDS =
            List.of("id", "host", "rule_id", "mitre", "domain", "dest_ip");

    @BeforeEach
    void routeReader() {
        eventRows.clear();
        alertRows.clear();
        when(reader.query(any())).thenAnswer(inv -> answer(inv.getArgument(0)));
    }

    /** 조회 종류를 SQL 모양으로 갈라 목 데이터를 돌려준다. */
    private List<Map<String, Object>> answer(ClickHouseQuery q) {
        String sql = q.sql();
        if (sql.contains("last_seen")) {
            return hostsLastSeen(q.params().get("tenant"));
        }
        if (sql.contains("positionCaseInsensitive")) {
            return sql.contains(" FINAL") ? searchAlerts(q) : searchEvents(q);
        }
        if (q.params().containsKey("host")) {
            return eventAt(q);   // 이벤트 단건 조회(검색 결과에서 넘어가는 경로)
        }
        return List.of();        // 호스트 위험도/열린 알림 집계는 검색 결과와 무관하다
    }

    private List<Map<String, Object>> searchEvents(ClickHouseQuery q) {
        return matched(eventRows, q, EVENT_FIELDS, List.of());
    }

    private List<Map<String, Object>> searchAlerts(ClickHouseQuery q) {
        List<String> ruleIds = q.params().entrySet().stream()
                .filter(e -> e.getKey().startsWith("rid"))
                .map(Map.Entry::getValue)
                .toList();
        return matched(alertRows, q, ALERT_FIELDS, ruleIds);
    }

    /** WHERE 절(tenant + 시간창 + 컬럼 OR 부분일치 + ruleId)과 ORDER BY/LIMIT 을 그대로 흉내 낸다. */
    private static List<Map<String, Object>> matched(List<Map<String, Object>> rows, ClickHouseQuery q,
                                                     List<String> fields, List<String> ruleIds) {
        String tenant = q.params().get("tenant");
        String term = q.params().get("q").toLowerCase(Locale.ROOT);
        return rows.stream()
                .filter(r -> tenant.equals(r.get("tenant_id")))
                .filter(r -> inRange(q.params(), r))
                .filter(r -> fields.stream().anyMatch(f -> text(r, f).toLowerCase(Locale.ROOT).contains(term))
                        || ruleIds.contains(text(r, "rule_id")))
                .sorted(Comparator.comparingLong((Map<String, Object> r) -> ts(r)).reversed())
                .limit(limitOf(q.sql()))
                .toList();
    }

    private List<Map<String, Object>> eventAt(ClickHouseQuery q) {
        String tenant = q.params().get("tenant");
        String host = q.params().get("host");
        return eventRows.stream()
                .filter(r -> tenant.equals(r.get("tenant_id")))
                .filter(r -> host.equals(r.get("host")))
                .filter(r -> inRange(q.params(), r))
                .toList();
    }

    /** events 집계(host, last_seen)를 목 데이터로 만든다. HostService 가 호스트 목록의 재료로 쓴다. */
    private List<Map<String, Object>> hostsLastSeen(String tenant) {
        Map<String, Long> lastSeen = new LinkedHashMap<>();
        eventRows.stream()
                .filter(r -> tenant.equals(r.get("tenant_id")))
                .forEach(r -> lastSeen.merge(text(r, "host"), ts(r), Math::max));
        return lastSeen.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .map(e -> Map.<String, Object>of("host", e.getKey(), "last_seen", String.valueOf(e.getValue())))
                .toList();
    }

    /** SQL 에 박힌 LIMIT 값(탐침 행 포함). 잘림 표시가 실제로 맞는지 보려면 목도 상한을 지켜야 한다. */
    private static long limitOf(String sql) {
        return Long.parseLong(sql.substring(sql.lastIndexOf("LIMIT ") + "LIMIT ".length()).trim());
    }

    private static boolean inRange(Map<String, String> params, Map<String, Object> row) {
        long ts = ts(row);
        String from = params.get("from");
        String to = params.get("to");
        return (from == null || ts >= Long.parseLong(from)) && (to == null || ts <= Long.parseLong(to));
    }

    private static long ts(Map<String, Object> row) {
        return Long.parseLong(String.valueOf(row.get("ts")));
    }

    private static String text(Map<String, Object> row, String key) {
        Object v = row.get(key);
        return v == null ? "" : String.valueOf(v);
    }

    // --- 시드 ---

    private void seedEvent(String tenantId, String host, long ts, String process, String cmdline, String domain) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("tenant_id", tenantId);
        row.put("host", host);
        row.put("type", "process");
        row.put("ts", String.valueOf(ts));
        row.put("process", process);
        row.put("parent", "launchd");
        row.put("cmdline", cmdline);
        row.put("dest_ip", "");
        row.put("dest_port", 0);
        row.put("domain", domain);
        row.put("detail", "{\"pid\":4321,\"ppid\":1}");
        row.put("sha256", "");
        row.put("ingested_at", "2026-07-31 00:00:00.000");
        eventRows.add(row);
    }

    private void seedAlert(String tenantId, String id, String host, String ruleId, long ts) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("tenant_id", tenantId);
        row.put("id", id);
        row.put("host", host);
        row.put("rule_id", ruleId);
        row.put("mitre", "T1105+T1204");
        row.put("severity", "HIGH");
        row.put("ts", String.valueOf(ts));
        row.put("domain", "malware.example.com");
        row.put("dest_ip", "203.0.113.7");
        alertRows.add(row);
    }

    private String[] signup(String email) throws Exception {
        MvcResult res = mvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"password1\"}"))
                .andExpect(status().isCreated())
                .andReturn();
        JsonNode node = om.readTree(res.getResponse().getContentAsString());
        return new String[]{node.get("token").asText(), node.get("tenantId").asText()};
    }

    /** 시각 고정이 필요한 테스트를 위해 기간을 명시할 수 있게 둔다(기본 기간은 최근 7일). */
    private JsonNode search(String token, String q, String... params) throws Exception {
        var request = get("/api/search").param("q", q)
                .header("Authorization", "Bearer " + token)
                .header("X-API-Key", API_KEY);
        for (int i = 0; i < params.length; i += 2) {
            request = request.param(params[i], params[i + 1]);
        }
        MvcResult res = mvc.perform(request).andExpect(status().isOk()).andReturn();
        return om.readTree(res.getResponse().getContentAsString());
    }

    private static long now() {
        return System.currentTimeMillis();
    }

    // --- 부분일치 ---

    @Test
    void 호스트명_일부만_쳐도_그_호스트와_이벤트가_나온다() throws Exception {
        // 기존 필터(?host=)는 완전일치라 이게 안 됐다. 이 기능이 있는 이유다.
        String[] a = signup("a-search-partial@edrdog.com");
        seedEvent(a[1], MAC, now(), "curl", "curl http://x", "");

        JsonNode body = search(a[0], "gimdong");
        assertOnly(body.at("/hosts/items"), MAC, "/host");
        assertOnly(body.at("/events/items"), MAC, "/host");
    }

    @Test
    void 프로세스명과_명령줄과_도메인으로도_찾는다() throws Exception {
        String[] a = signup("a-search-fields@edrdog.com");
        seedEvent(a[1], MAC, now(), "osascript", "osascript -e 'do shell script'", "");
        seedEvent(a[1], "web-01", now(), "curl", "curl -sL https://cdn.example.com", "cdn.example.com");

        assertOnly(search(a[0], "osascr").at("/events/items"), "osascript", "/process");
        assertOnly(search(a[0], "shell script").at("/events/items"), "osascript", "/process");
        assertOnly(search(a[0], "cdn.example").at("/events/items"), "curl", "/process");
    }

    @Test
    void 대소문자를_가리지_않는다() throws Exception {
        // 도메인과 해시는 소문자로 적재된다. 대문자로 쳐도 같은 것을 찾아야 한다.
        String[] a = signup("a-search-case@edrdog.com");
        seedEvent(a[1], MAC, now(), "curl", "curl https://cdn.example.com", "cdn.example.com");

        assertOnly(search(a[0], "GIMDONG").at("/hosts/items"), MAC, "/host");
        assertOnly(search(a[0], "CDN.EXAMPLE").at("/events/items"), MAC, "/host");
        assertOnly(search(a[0], "MacBookPro").at("/hosts/items"), MAC, "/host");
    }

    @Test
    void 한글_위협명으로_알림을_찾는다() throws Exception {
        // 화면에는 한글 위협명이 보인다. ClickHouse 에는 영문 ruleId 만 있으니 그대로면 못 찾는다.
        String[] a = signup("a-search-threat@edrdog.com");
        seedAlert(a[1], "alert-1", MAC, "DOWNLOAD_AND_EXECUTE", now());

        JsonNode items = search(a[0], "다운로드 후").at("/alerts/items");
        assertOnly(items, "alert-1", "/id");
        assertEquals("다운로드 후 실행", items.get(0).at("/threatName").asText());
    }

    @Test
    void 알림_id_를_붙여넣어도_찾는다() throws Exception {
        String[] a = signup("a-search-alertid@edrdog.com");
        seedAlert(a[1], "8f14e45f-ea16-4d63-9f9b-2b6f9b1f0a11", MAC, "DOWNLOAD_AND_EXECUTE", now());

        assertOnly(search(a[0], "8f14e45f-ea16").at("/alerts/items"),
                "8f14e45f-ea16-4d63-9f9b-2b6f9b1f0a11", "/id");
    }

    // --- 격리 ---

    @Test
    void 남의_tenant_결과는_한_건도_섞이지_않는다() throws Exception {
        String[] a = signup("a-search-iso@edrdog.com");
        String[] b = signup("b-search-iso@edrdog.com");
        seedEvent(b[1], MAC, now(), "curl", "curl http://x", "");
        seedAlert(b[1], "alert-b", MAC, "DOWNLOAD_AND_EXECUTE", now());

        JsonNode body = search(a[0], "gimdong");
        assertEmpty(body, "/hosts");
        assertEmpty(body, "/events");
        assertEmpty(body, "/alerts");
    }

    @Test
    void 토큰이_없으면_401() throws Exception {
        mvc.perform(get("/api/search").param("q", "gimdong").header("X-API-Key", API_KEY))
                .andExpect(status().isUnauthorized());
    }

    // --- 질의어 방어 ---

    @Test
    void 너무_짧거나_없는_검색어는_400() throws Exception {
        String[] a = signup("a-search-short@edrdog.com");

        for (String q : List.of("a", " ", "")) {
            mvc.perform(get("/api/search").param("q", q)
                            .header("Authorization", "Bearer " + a[0])
                            .header("X-API-Key", API_KEY))
                    .andExpect(status().isBadRequest());
        }
        mvc.perform(get("/api/search")
                        .header("Authorization", "Bearer " + a[0])
                        .header("X-API-Key", API_KEY))
                .andExpect(status().isBadRequest());
    }

    @Test
    void 지나치게_긴_검색어는_400() throws Exception {
        String[] a = signup("a-search-long@edrdog.com");

        mvc.perform(get("/api/search").param("q", "a".repeat(SearchTerm.MAX_LENGTH + 1))
                        .header("Authorization", "Bearer " + a[0])
                        .header("X-API-Key", API_KEY))
                .andExpect(status().isBadRequest());
    }

    @Test
    void 와일드카드_문자를_쳐도_전체가_나오지_않는다() throws Exception {
        // LIKE 였다면 %가 "전부" 라서 상단바 한 번이 전체 스캔 결과를 그대로 돌려준다.
        String[] a = signup("a-search-wildcard@edrdog.com");
        seedEvent(a[1], MAC, now(), "curl", "curl http://x", "");
        seedAlert(a[1], "alert-1", MAC, "DOWNLOAD_AND_EXECUTE", now());

        JsonNode body = search(a[0], "%_");
        assertEmpty(body, "/hosts");
        assertEmpty(body, "/events");
        assertEmpty(body, "/alerts");
    }

    @Test
    void 인젝션_시도_문자열은_그냥_안_맞는_검색어다() throws Exception {
        String[] a = signup("a-search-inject@edrdog.com");
        seedEvent(a[1], MAC, now(), "curl", "curl http://x", "");

        assertEmpty(search(a[0], "' OR 1=1 --"), "/events");
    }

    // --- 비용 묶기 ---

    @Test
    void 종류별_상한을_넘으면_잘라내고_잘렸다고_말한다() throws Exception {
        // 상단바에서 "이게 전부" 로 읽히면 조사에서 놓친다.
        String[] a = signup("a-search-trunc@edrdog.com");
        for (int i = 0; i < 5; i++) {
            seedEvent(a[1], MAC, now() - i, "curl" + i, "curl http://x", "");
        }

        JsonNode body = search(a[0], "gimdong", "limit", "2");
        assertEquals(2, body.at("/events/items").size());
        assertTrue(body.at("/events/hasMore").asBoolean());
        // 호스트는 한 대뿐이라 잘리지 않는다. 섹션마다 따로 말해야 하는 이유다.
        assertFalse(body.at("/hosts/hasMore").asBoolean());
    }

    @Test
    void 기본_기간_밖의_이벤트는_안_나오고_기간을_넓히면_나온다() throws Exception {
        // 부분일치는 인덱스를 못 쓰므로 기간이 스캔 범위를 정한다. 기본은 최근 7일이다.
        String[] a = signup("a-search-window@edrdog.com");
        long eightDaysAgo = now() - 8L * 24 * 60 * 60 * 1000;
        seedEvent(a[1], MAC, eightDaysAgo, "curl", "curl http://x", "");

        assertEmpty(search(a[0], "gimdong"), "/events");
        assertOnly(search(a[0], "gimdong", "from", "0").at("/events/items"), MAC, "/host");
    }

    @Test
    void 적용된_기간을_응답에_실어_준다() throws Exception {
        String[] a = signup("a-search-applied@edrdog.com");

        JsonNode body = search(a[0], "gimdong", "from", "1000", "to", "2000");
        assertEquals(1000L, body.at("/from").asLong());
        assertEquals(2000L, body.at("/to").asLong());
        assertEquals("gimdong", body.at("/query").asText());
    }

    // --- 결과에서 이동 ---

    @Test
    void 검색_결과의_이벤트를_그대로_단건_조회로_연다() throws Exception {
        // 결과가 쓸모 있으려면 화면이 그 항목으로 바로 넘어갈 수 있어야 한다.
        String[] a = signup("a-search-navigate@edrdog.com");
        seedEvent(a[1], MAC, now(), "curl", "curl http://x", "");

        JsonNode hit = search(a[0], "gimdong").at("/events/items").get(0);
        mvc.perform(get("/api/events/" + hit.get("id").asText())
                        .param("host", hit.get("host").asText())
                        .param("ts", hit.get("ts").asText())
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(hit.get("id").asText()))
                .andExpect(jsonPath("$.process").value("curl"));
    }

    // --- 도우미 ---

    private static void assertOnly(JsonNode items, String expected, String pointer) {
        assertEquals(1, items.size(), items.toString());
        assertEquals(expected, items.get(0).at(pointer).asText());
    }

    private static void assertEmpty(JsonNode body, String section) {
        assertEquals(0, body.at(section + "/items").size(),
                body.at(section).toString());
        assertFalse(body.at(section + "/hasMore").asBoolean());
    }
}
