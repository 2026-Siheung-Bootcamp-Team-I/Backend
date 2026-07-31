package com.edrdog.apiservice.alert.web;

import com.edrdog.apiservice.alert.AlertId;
import com.edrdog.apiservice.alert.AlertQueryBuilder;
import com.edrdog.apiservice.alert.AlertStatus;
import com.edrdog.apiservice.clickhouse.ClickHouseReader;
import com.edrdog.apiservice.query.ClickHouseQuery;
import com.edrdog.apiservice.responder.ResponderClient;
import com.edrdog.apiservice.web.PageHeaders;
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * GET /api/alerts 페이지네이션 배선 검증. 목 ClickHouse 가 tenant/시간/IN·NOT IN 필터뿐 아니라
 * ORDER BY ts DESC 와 LIMIT/OFFSET, count() 까지 흉내 낸다(그러지 않으면 offset 검증이 성립하지 않는다).
 */
@SpringBootTest
@AutoConfigureMockMvc
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.ANY)
@TestPropertySource(properties = "spring.kafka.listener.auto-startup=false")
class AlertPaginationApiIntegrationTest {

    private static final Pattern LIMIT = Pattern.compile("LIMIT (\\d+)");
    private static final Pattern OFFSET = Pattern.compile("OFFSET (\\d+)");

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper om;

    @MockitoBean
    private ClickHouseReader reader;

    @MockitoBean
    private ResponderClient responder;

    private final List<Map<String, Object>> alertRows = new ArrayList<>();

    private String lastSql;

    @BeforeEach
    void routeReader() {
        alertRows.clear();
        lastSql = null;
        when(reader.query(any())).thenAnswer(inv -> {
            ClickHouseQuery q = inv.getArgument(0);
            lastSql = q.sql();
            String tenant = q.params().get("tenant");
            List<Map<String, Object>> matched = alertRows.stream()
                    .filter(r -> tenant.equals(r.get("tenant_id")))
                    .filter(r -> !q.params().containsKey("id") || q.params().get("id").equals(r.get("id")))
                    .filter(r -> inRange(q.params(), r))
                    .filter(r -> included(q, r))
                    .filter(r -> !excluded(q, r))
                    .sorted(Comparator.comparingLong(AlertPaginationApiIntegrationTest::ts).reversed())
                    .toList();
            if (q.sql().contains("count() AS cnt")) {
                return List.of(Map.of("cnt", String.valueOf(matched.size())));
            }
            return slice(matched, q.sql());
        });
    }

    /** ClickHouse 의 LIMIT/OFFSET 을 그대로 흉내 낸다. */
    private static List<Map<String, Object>> slice(List<Map<String, Object>> rows, String sql) {
        int offset = group(OFFSET, sql, 0);
        int limit = group(LIMIT, sql, Integer.MAX_VALUE);
        if (offset >= rows.size()) {
            return List.of();
        }
        return rows.subList(offset, Math.min(rows.size(), offset + limit));
    }

    private static int group(Pattern p, String sql, int fallback) {
        Matcher m = p.matcher(sql);
        return m.find() ? Integer.parseInt(m.group(1)) : fallback;
    }

    /** id IN (...) 을 흉내 낸다(조건이 없으면 통과). */
    private static boolean included(ClickHouseQuery q, Map<String, Object> row) {
        return !q.sql().contains("id IN (") || idSet(q, "inc").contains(String.valueOf(row.get("id")));
    }

    /** id NOT IN (...) 을 흉내 낸다. */
    private static boolean excluded(ClickHouseQuery q, Map<String, Object> row) {
        return q.sql().contains("id NOT IN (") && idSet(q, "exc").contains(String.valueOf(row.get("id")));
    }

    private static List<String> idSet(ClickHouseQuery q, String prefix) {
        return q.params().entrySet().stream()
                .filter(e -> e.getKey().matches(prefix + "\\d+"))
                .map(Map.Entry::getValue)
                .toList();
    }

    /** 빌더가 만드는 ts >= from AND ts < to 를 그대로 흉내 낸다. */
    private static boolean inRange(Map<String, String> params, Map<String, Object> row) {
        long ts = ts(row);
        String from = params.get("from");
        String to = params.get("to");
        return (from == null || ts >= Long.parseLong(from)) && (to == null || ts < Long.parseLong(to));
    }

    private static long ts(Map<String, Object> row) {
        return Long.parseLong(String.valueOf(row.get("ts")));
    }

    private String[] signup(String email) throws Exception {
        MvcResult res = mvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"password1\"}"))
                .andExpect(status().isCreated())
                .andReturn();
        var node = om.readTree(res.getResponse().getContentAsString());
        return new String[]{node.get("token").asText(), node.get("tenantId").asText()};
    }

    private String seedAlert(String tenantId, String host, String ruleId, long ts) {
        String id = AlertId.of(tenantId, host, ruleId, ts);
        Map<String, Object> row = new HashMap<>(Map.of(
                "id", id, "tenant_id", tenantId, "host", host, "rule_id", ruleId,
                "mitre", "T1059", "severity", "HIGH", "action", "notify",
                "ts", String.valueOf(ts), "matched", List.of("m1")));
        row.put("domain", "evil.example.com");
        row.put("dest_ip", "203.0.113.9");
        alertRows.add(row);
        return id;
    }

    /** 최근 1분 안의 시각으로 알림 n 건을 시드한다(반환값은 기준 시각). */
    private long seedRecent(String tenantId, int count) {
        long base = System.currentTimeMillis() - 60_000;
        for (int i = 1; i <= count; i++) {
            seedAlert(tenantId, "hostA", "RULE_" + i, base + i);
        }
        return base;
    }

    private List<String> ruleIds(MvcResult res) throws Exception {
        List<String> out = new ArrayList<>();
        om.readTree(res.getResponse().getContentAsString()).forEach(n -> out.add(n.get("ruleId").asText()));
        return out;
    }

    @Test
    void offset_은_실제로_그만큼_건너뛴다() throws Exception {
        String[] a = signup("a-alpage-skip@edrdog.com");
        seedRecent(a[1], 5);

        MvcResult page1 = mvc.perform(get("/api/alerts").param("limit", "2")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andReturn();
        MvcResult page2 = mvc.perform(get("/api/alerts").param("limit", "2").param("offset", "2")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andReturn();

        assertEquals(List.of("RULE_5", "RULE_4"), ruleIds(page1));
        assertEquals(List.of("RULE_3", "RULE_2"), ruleIds(page2));
    }

    @Test
    void offset_을_안_주면_예전과_같이_동작한다() throws Exception {
        String[] a = signup("a-alpage-none@edrdog.com");
        seedRecent(a[1], 3);

        mvc.perform(get("/api/alerts").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(3))
                .andExpect(jsonPath("$[0].status").value("open"));
        assertTrue(!lastSql.contains("OFFSET"), lastSql);
    }

    @Test
    void 응답_본문은_지금처럼_배열이고_페이지_정보는_헤더로_나간다() throws Exception {
        String[] a = signup("a-alpage-shape@edrdog.com");
        seedRecent(a[1], 3);

        mvc.perform(get("/api/alerts").param("limit", "2").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(2))
                .andExpect(header().string(PageHeaders.HAS_MORE, "true"))
                .andExpect(header().exists(PageHeaders.TIME_TO))
                .andExpect(header().string(PageHeaders.TIME_FROM, "0"))
                // FINAL + count 는 비싸다. 요청하지 않으면 세지 않는다.
                .andExpect(header().doesNotExist(PageHeaders.TOTAL_COUNT));
    }

    @Test
    void 마지막_페이지는_다음이_없다고_알린다() throws Exception {
        String[] a = signup("a-alpage-last@edrdog.com");
        seedRecent(a[1], 3);

        mvc.perform(get("/api/alerts").param("limit", "2").param("offset", "2")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(header().string(PageHeaders.HAS_MORE, "false"));
    }

    @Test
    void offset_이_상한을_넘으면_400() throws Exception {
        String[] a = signup("a-alpage-max@edrdog.com");

        mvc.perform(get("/api/alerts").param("offset", String.valueOf(AlertQueryBuilder.MAX_OFFSET + 1))
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isBadRequest());
        mvc.perform(get("/api/alerts").param("offset", "-1")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isBadRequest());
    }

    @Test
    void 총건수는_요청했을_때만_세고_남의_tenant_는_안_센다() throws Exception {
        // 남의 조직 건수가 총계에 섞이면 그 자체로 정보가 샌다.
        String[] a = signup("a-alpage-total@edrdog.com");
        String[] b = signup("b-alpage-total@edrdog.com");
        seedRecent(a[1], 3);
        long base = System.currentTimeMillis() - 30_000;
        for (int i = 1; i <= 7; i++) {
            seedAlert(b[1], "hostB", "OTHER_" + i, base + i);
        }

        mvc.perform(get("/api/alerts").param("limit", "2").param("withTotal", "true")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(header().string(PageHeaders.TOTAL_COUNT, "3"));
        mvc.perform(get("/api/alerts").param("limit", "2").param("withTotal", "true")
                        .header("Authorization", "Bearer " + b[0]))
                .andExpect(status().isOk())
                .andExpect(header().string(PageHeaders.TOTAL_COUNT, "7"));
    }

    @Test
    void 총건수는_status_필터를_건_뒤의_건수다() throws Exception {
        // status 는 오버레이(MySQL)에서 계산해 SQL 의 IN/NOT IN 으로 옮긴다. 총계도 같은 조건이어야 한다.
        String[] a = signup("a-alpage-totalstatus@edrdog.com");
        seedRecent(a[1], 4);
        String confirmed = alertRows.get(0).get("id").toString();
        mvc.perform(patch("/api/alerts/" + confirmed)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"status\":\"" + AlertStatus.CONFIRMED + "\"}")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk());

        mvc.perform(get("/api/alerts").param("status", "open").param("withTotal", "true")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(header().string(PageHeaders.TOTAL_COUNT, "3"));
        mvc.perform(get("/api/alerts").param("status", AlertStatus.CONFIRMED).param("withTotal", "true")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(header().string(PageHeaders.TOTAL_COUNT, "1"));
    }

    @Test
    void 응답이_알려준_시간범위를_고정하면_페이지가_겹치거나_빠지지_않는다() throws Exception {
        String[] a = signup("a-alpage-pin@edrdog.com");
        seedRecent(a[1], 4);

        MvcResult page1 = mvc.perform(get("/api/alerts").param("limit", "2")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andReturn();
        String pinnedTo = page1.getResponse().getHeader(PageHeaders.TIME_TO);

        // 첫 페이지를 본 뒤 새 알림이 들어온다
        seedAlert(a[1], "hostA", "NEW_1", Long.parseLong(pinnedTo) + 1);
        seedAlert(a[1], "hostA", "NEW_2", Long.parseLong(pinnedTo) + 2);

        MvcResult page2 = mvc.perform(get("/api/alerts")
                        .param("limit", "2").param("offset", "2").param("to", pinnedTo)
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andReturn();

        assertEquals(List.of("RULE_4", "RULE_3"), ruleIds(page1));
        assertEquals(List.of("RULE_2", "RULE_1"), ruleIds(page2));
    }

    @Test
    void 시간범위를_고정하지_않으면_새_알림_때문에_페이지가_겹친다() throws Exception {
        // 고정이 왜 필요한지 고정해 두는 테스트.
        String[] a = signup("a-alpage-nopin@edrdog.com");
        seedRecent(a[1], 4);

        MvcResult page1 = mvc.perform(get("/api/alerts").param("limit", "2")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andReturn();
        String pinnedTo = page1.getResponse().getHeader(PageHeaders.TIME_TO);
        seedAlert(a[1], "hostA", "NEW_1", Long.parseLong(pinnedTo) + 1);
        seedAlert(a[1], "hostA", "NEW_2", Long.parseLong(pinnedTo) + 2);

        MvcResult page2 = mvc.perform(get("/api/alerts")
                        .param("limit", "2").param("offset", "2")
                        .param("to", String.valueOf(Long.parseLong(pinnedTo) + 10))
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andReturn();

        assertEquals(ruleIds(page1), ruleIds(page2));   // 1페이지가 통째로 다시 나온다
    }

    @Test
    void 페이지네이션에도_tenant_격리는_그대로다() throws Exception {
        String[] a = signup("a-alpage-iso@edrdog.com");
        String[] b = signup("b-alpage-iso@edrdog.com");
        seedRecent(a[1], 5);

        mvc.perform(get("/api/alerts").param("limit", "2").param("offset", "0").param("withTotal", "true")
                        .header("Authorization", "Bearer " + b[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(0))
                .andExpect(header().string(PageHeaders.HAS_MORE, "false"))
                .andExpect(header().string(PageHeaders.TOTAL_COUNT, "0"));
    }
}
