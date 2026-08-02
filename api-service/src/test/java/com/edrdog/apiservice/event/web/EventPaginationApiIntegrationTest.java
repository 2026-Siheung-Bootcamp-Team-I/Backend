package com.edrdog.apiservice.event.web;

import com.edrdog.apiservice.clickhouse.ClickHouseReader;
import com.edrdog.apiservice.query.ClickHouseQuery;
import com.edrdog.apiservice.query.EventQueryBuilder;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * GET /api/events 페이지네이션 배선 검증.
 *
 * <p>여기서 봐야 하는 건 "offset 이 실제로 건너뛰는가" 와 "시간 범위를 고정하면 페이지가 겹치거나
 * 빠지지 않는가" 다. 그래서 목 ClickHouse 가 tenant/시간 필터뿐 아니라 ORDER BY ts DESC 와
 * LIMIT/OFFSET, count() 까지 흉내 낸다. 목이 그것을 무시하면 이 검증은 성립하지 않는다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.ANY)
@TestPropertySource(properties = "spring.kafka.listener.auto-startup=false")
class EventPaginationApiIntegrationTest {

    private static final Pattern LIMIT = Pattern.compile("LIMIT (\\d+)");
    private static final Pattern OFFSET = Pattern.compile("OFFSET (\\d+)");

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper om;

    @MockitoBean
    private ClickHouseReader reader;

    private final List<Map<String, Object>> eventRows = new ArrayList<>();

    /** 마지막 조회에 쓰인 SQL. offset 없는 요청이 예전과 같은 SQL 인지 보려면 필요하다. */
    private String lastSql;

    @BeforeEach
    void routeReader() {
        eventRows.clear();
        lastSql = null;
        when(reader.query(any())).thenAnswer(inv -> {
            ClickHouseQuery q = inv.getArgument(0);
            lastSql = q.sql();
            String tenant = q.params().get("tenant");
            List<Map<String, Object>> matched = eventRows.stream()
                    .filter(r -> tenant.equals(r.get("tenant_id")))
                    .filter(r -> inRange(q.params(), r))
                    .sorted(Comparator.comparingLong(EventPaginationApiIntegrationTest::ts).reversed())
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

    private static boolean inRange(Map<String, String> params, Map<String, Object> row) {
        long ts = ts(row);
        String from = params.get("from");
        String to = params.get("to");
        return (from == null || ts >= Long.parseLong(from)) && (to == null || ts <= Long.parseLong(to));
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

    private void seedEvent(String tenantId, String host, long ts, String process) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("tenant_id", tenantId);
        row.put("host", host);
        row.put("type", "process");
        row.put("ts", String.valueOf(ts));
        row.put("process", process);
        row.put("parent", "explorer.exe");
        row.put("cmdline", "C:\\Users\\Public\\" + process);
        row.put("dest_ip", "");
        row.put("dest_port", 0);
        row.put("domain", "");
        row.put("detail", "{}");
        row.put("sha256", "");
        row.put("ingested_at", "2026-07-31 00:00:00.000");
        eventRows.add(row);
    }

    /** 응답 배열의 process 목록(어떤 행이 실렸는지 확인용). */
    private List<String> processes(MvcResult res) throws Exception {
        List<String> out = new ArrayList<>();
        om.readTree(res.getResponse().getContentAsString()).forEach(n -> out.add(n.get("process").asText()));
        return out;
    }

    /** 최근 1분 안의 시각으로 이벤트 n 건을 시드한다(반환값은 기준 시각). */
    private long seedRecent(String tenantId, int count) {
        long base = System.currentTimeMillis() - 60_000;
        for (int i = 1; i <= count; i++) {
            seedEvent(tenantId, "hostA", base + i, "p" + i);
        }
        return base;
    }

    @Test
    void offset_은_실제로_그만큼_건너뛴다() throws Exception {
        String[] a = signup("a-evpage-skip@edrdog.com");
        seedRecent(a[1], 5);

        MvcResult page1 = mvc.perform(get("/api/events").param("limit", "2")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andReturn();
        MvcResult page2 = mvc.perform(get("/api/events").param("limit", "2").param("offset", "2")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andReturn();

        assertEquals(List.of("p5", "p4"), processes(page1));
        assertEquals(List.of("p3", "p2"), processes(page2));
    }

    @Test
    void offset_을_안_주면_예전과_같이_동작한다() throws Exception {
        String[] a = signup("a-evpage-none@edrdog.com");
        seedRecent(a[1], 3);

        mvc.perform(get("/api/events").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(3))
                .andExpect(jsonPath("$[0].process").value("p3"));
        assertTrue(!lastSql.contains("OFFSET"), lastSql);
    }

    @Test
    void 응답_본문은_지금처럼_배열이고_페이지_정보는_헤더로_나간다() throws Exception {
        String[] a = signup("a-evpage-shape@edrdog.com");
        seedRecent(a[1], 3);

        mvc.perform(get("/api/events").param("limit", "2").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(2))
                .andExpect(header().string(PageHeaders.HAS_MORE, "true"))
                .andExpect(header().exists(PageHeaders.TIME_TO))
                .andExpect(header().string(PageHeaders.TIME_FROM, "0"))
                // 총계는 요청하지 않았으니 세지도 않는다
                .andExpect(header().doesNotExist(PageHeaders.TOTAL_COUNT));
    }

    @Test
    void 마지막_페이지는_다음이_없다고_알린다() throws Exception {
        String[] a = signup("a-evpage-last@edrdog.com");
        seedRecent(a[1], 3);

        mvc.perform(get("/api/events").param("limit", "2").param("offset", "2")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(header().string(PageHeaders.HAS_MORE, "false"));
    }

    @Test
    void offset_이_상한을_넘으면_400() throws Exception {
        // 조용히 잘라 상한 페이지를 주면 화면은 자기가 요청한 페이지가 비어 있다고 읽는다.
        String[] a = signup("a-evpage-max@edrdog.com");

        mvc.perform(get("/api/events").param("offset", String.valueOf(EventQueryBuilder.MAX_OFFSET + 1))
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isBadRequest());
        mvc.perform(get("/api/events").param("offset", "-1")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isBadRequest());
    }

    @Test
    void 총건수는_요청했을_때만_세고_남의_tenant_는_안_센다() throws Exception {
        // 남의 조직 건수가 총계에 섞이면 그 자체로 정보가 샌다.
        String[] a = signup("a-evpage-total@edrdog.com");
        String[] b = signup("b-evpage-total@edrdog.com");
        seedRecent(a[1], 3);
        for (int i = 1; i <= 7; i++) {
            seedEvent(b[1], "hostB", System.currentTimeMillis() - 30_000 + i, "other" + i);
        }

        mvc.perform(get("/api/events").param("limit", "2").param("withTotal", "true")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(header().string(PageHeaders.TOTAL_COUNT, "3"));
        mvc.perform(get("/api/events").param("limit", "2").param("withTotal", "true")
                        .header("Authorization", "Bearer " + b[0]))
                .andExpect(status().isOk())
                .andExpect(header().string(PageHeaders.TOTAL_COUNT, "7"));
    }

    @Test
    void 총건수는_필터를_건_뒤의_건수다() throws Exception {
        String[] a = signup("a-evpage-totalfilter@edrdog.com");
        long base = seedRecent(a[1], 5);

        mvc.perform(get("/api/events")
                        .param("limit", "2").param("withTotal", "true")
                        .param("from", String.valueOf(base + 3))
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(header().string(PageHeaders.TOTAL_COUNT, "3"))
                .andExpect(header().string(PageHeaders.TIME_FROM, String.valueOf(base + 3)));
    }

    @Test
    void 응답이_알려준_시간범위를_고정하면_페이지가_겹치거나_빠지지_않는다() throws Exception {
        String[] a = signup("a-evpage-pin@edrdog.com");
        seedRecent(a[1], 4);

        MvcResult page1 = mvc.perform(get("/api/events").param("limit", "2")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andReturn();
        String pinnedTo = page1.getResponse().getHeader(PageHeaders.TIME_TO);

        // 첫 페이지를 본 뒤 새 이벤트가 들어온다(실제 조사 중에 늘 일어나는 일이다)
        seedEvent(a[1], "hostA", Long.parseLong(pinnedTo) + 1, "new1");
        seedEvent(a[1], "hostA", Long.parseLong(pinnedTo) + 2, "new2");

        MvcResult page2 = mvc.perform(get("/api/events")
                        .param("limit", "2").param("offset", "2").param("to", pinnedTo)
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andReturn();

        assertEquals(List.of("p4", "p3"), processes(page1));
        assertEquals(List.of("p2", "p1"), processes(page2));   // 겹치지도, 빠지지도 않는다
    }

    @Test
    void 시간범위를_고정하지_않으면_새_이벤트_때문에_페이지가_겹친다() throws Exception {
        // 고정이 왜 필요한지 고정해 두는 테스트. to 를 새로 잡으면 새 행이 맨 위에 쌓여 offset 이 밀린다.
        String[] a = signup("a-evpage-nopin@edrdog.com");
        seedRecent(a[1], 4);

        MvcResult page1 = mvc.perform(get("/api/events").param("limit", "2")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andReturn();
        String pinnedTo = page1.getResponse().getHeader(PageHeaders.TIME_TO);
        seedEvent(a[1], "hostA", Long.parseLong(pinnedTo) + 1, "new1");
        seedEvent(a[1], "hostA", Long.parseLong(pinnedTo) + 2, "new2");

        MvcResult page2 = mvc.perform(get("/api/events")
                        .param("limit", "2").param("offset", "2")
                        .param("to", String.valueOf(Long.parseLong(pinnedTo) + 10))
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andReturn();

        assertEquals(processes(page1), processes(page2));   // 1페이지가 통째로 다시 나온다
    }

    @Test
    void 페이지네이션에도_tenant_격리는_그대로다() throws Exception {
        String[] a = signup("a-evpage-iso@edrdog.com");
        String[] b = signup("b-evpage-iso@edrdog.com");
        seedRecent(a[1], 5);

        mvc.perform(get("/api/events").param("limit", "2").param("offset", "0")
                        .header("Authorization", "Bearer " + b[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(0))
                .andExpect(header().string(PageHeaders.HAS_MORE, "false"));
    }
}
