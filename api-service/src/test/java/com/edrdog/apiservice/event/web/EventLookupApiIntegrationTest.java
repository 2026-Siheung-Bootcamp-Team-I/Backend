package com.edrdog.apiservice.event.web;

import com.edrdog.apiservice.clickhouse.ClickHouseReader;
import com.edrdog.apiservice.event.EventId;
import com.edrdog.apiservice.query.ClickHouseQuery;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * GET /api/events/{id} 배선 검증. 화면이 이벤트 하나를 링크로 지목해 여는 경로다.
 *
 * <p>id 는 저장된 값이 아니라 이벤트 내용을 접어 만든 것이라(EventId) 조회 조건으로 쓸 수 없다.
 * 그래서 이 테스트들은 id 를 직접 계산해 넣지 않고 목록(GET /api/events)이 준 id 를 그대로 들고 간다.
 * 목록이 준 링크가 실제로 열리는지가 이 기능의 계약이고, 두 경로가 같은 방식으로 id 를 접는지도 같이 고정된다.
 *
 * <p>ClickHouse 는 목으로 대체하되 tenant/host/시간창 필터는 흉내 낸다. 격리와 창 폭이 이 기능의
 * 핵심이라 목이 그것을 무시하면 검증이 성립하지 않는다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.ANY)
@TestPropertySource(properties = "spring.kafka.listener.auto-startup=false")
class EventLookupApiIntegrationTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper om;

    @MockitoBean
    private ClickHouseReader reader;

    /** 목 ClickHouse 의 events 행. tenant/host/시간창은 목이 쿼리 파라미터로 반영한다. */
    private final List<Map<String, Object>> eventRows = new ArrayList<>();

    @BeforeEach
    void routeReader() {
        eventRows.clear();
        when(reader.query(any())).thenAnswer(inv -> {
            ClickHouseQuery q = inv.getArgument(0);
            String tenant = q.params().get("tenant");
            String host = q.params().get("host");
            return eventRows.stream()
                    .filter(r -> tenant.equals(r.get("tenant_id")))
                    .filter(r -> host == null || host.equals(r.get("host")))
                    .filter(r -> inRange(q.params(), r))
                    .toList();
        });
    }

    /** 빌더가 만드는 ts >= from AND ts <= to 를 그대로 흉내 낸다(창 폭이 맞는지 검증하려면 필요하다). */
    private static boolean inRange(Map<String, String> params, Map<String, Object> row) {
        long ts = Long.parseLong(String.valueOf(row.get("ts")));
        String from = params.get("from");
        String to = params.get("to");
        return (from == null || ts >= Long.parseLong(from)) && (to == null || ts <= Long.parseLong(to));
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

    /** 이벤트 한 건을 목 ClickHouse 에 시드한다(ts 는 CH UInt64 처럼 문자열). */
    private void seedEvent(String tenantId, String host, long ts, String process, int pid) {
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
        row.put("detail", "{\"pid\":" + pid + ",\"ppid\":1}");
        row.put("sha256", "");
        row.put("ingested_at", "2026-07-31 00:00:00.000");
        eventRows.add(row);
    }

    /** 목록이 준 id. 링크는 이 값으로 만들어지므로 단건 조회도 이 값으로 열려야 한다. */
    private List<String> listedIds(String token) throws Exception {
        MvcResult res = mvc.perform(get("/api/events").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andReturn();
        List<String> ids = new ArrayList<>();
        om.readTree(res.getResponse().getContentAsString()).forEach(n -> ids.add(n.get("id").asText()));
        return ids;
    }

    @Test
    void 목록이_준_id_로_그_이벤트를_그대로_연다() throws Exception {
        String[] a = signup("a-evlookup@edrdog.com");
        seedEvent(a[1], "hostA", 10_000L, "evil.exe", 4321);
        String id = listedIds(a[0]).get(0);

        mvc.perform(get("/api/events/" + id)
                        .param("host", "hostA")
                        .param("ts", "10000")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(id))
                .andExpect(jsonPath("$.host").value("hostA"))
                .andExpect(jsonPath("$.ts").value(10_000L))
                .andExpect(jsonPath("$.process").value("evil.exe"))
                .andExpect(jsonPath("$.parent").value("explorer.exe"))
                .andExpect(jsonPath("$.cmdline").value("C:\\Users\\Public\\evil.exe"))
                .andExpect(jsonPath("$.pid").value(4321));
    }

    @Test
    void 같은_host_같은_시각에_여러_건이어도_id_가_가리키는_하나를_고른다() throws Exception {
        // 이 기능의 핵심이다. 시각으로 아무거나 고르면 링크가 조용히 다른 이벤트를 보여 준다.
        String[] a = signup("a-evsamets@edrdog.com");
        seedEvent(a[1], "hostA", 10_000L, "evil.exe", 4321);
        seedEvent(a[1], "hostA", 10_000L, "notepad.exe", 8765);
        List<String> ids = listedIds(a[0]);

        mvc.perform(get("/api/events/" + ids.get(0))
                        .param("host", "hostA").param("ts", "10000")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.process").value("evil.exe"));
        mvc.perform(get("/api/events/" + ids.get(1))
                        .param("host", "hostA").param("ts", "10000")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.process").value("notepad.exe"));
    }

    @Test
    void 창_안에_다른_이벤트가_있어도_id_가_안_맞으면_그것을_주지_않는다() throws Exception {
        String[] a = signup("a-evneighbor@edrdog.com");
        seedEvent(a[1], "hostA", 10_000L, "evil.exe", 4321);
        seedEvent(a[1], "hostA", 10_500L, "notepad.exe", 8765);
        String evilId = listedIds(a[0]).get(0);

        // ts 를 이웃 쪽으로 밀어 조회해도 창 안에서 id 가 맞는 행만 나온다
        mvc.perform(get("/api/events/" + evilId)
                        .param("host", "hostA").param("ts", "10500")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(evilId));
    }

    @Test
    void ts_가_초_단위로_잘려_와도_찾는다() throws Exception {
        // 창을 ts 한 점으로 못 박지 않은 이유. 링크가 나르는 ts 는 화면을 거치며 어긋날 수 있다.
        String[] a = signup("a-evtrunc@edrdog.com");
        seedEvent(a[1], "hostA", 10_750L, "evil.exe", 4321);
        String id = listedIds(a[0]).get(0);

        mvc.perform(get("/api/events/" + id)
                        .param("host", "hostA").param("ts", "10000")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(id))
                .andExpect(jsonPath("$.ts").value(10_750L));
    }

    @Test
    void 없는_id_는_404() throws Exception {
        String[] a = signup("a-evnotfound@edrdog.com");
        seedEvent(a[1], "hostA", 10_000L, "evil.exe", 4321);

        mvc.perform(get("/api/events/00000000-0000-0000-0000-000000000000")
                        .param("host", "hostA").param("ts", "10000")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isNotFound());
    }

    @Test
    void host_나_ts_가_창_밖이면_404() throws Exception {
        String[] a = signup("a-evwrongctx@edrdog.com");
        seedEvent(a[1], "hostA", 10_000L, "evil.exe", 4321);
        String id = listedIds(a[0]).get(0);

        mvc.perform(get("/api/events/" + id)
                        .param("host", "hostB").param("ts", "10000")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isNotFound());
        mvc.perform(get("/api/events/" + id)
                        .param("host", "hostA").param("ts", "99999999")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isNotFound());
    }

    @Test
    void 남의_tenant_이벤트는_404() throws Exception {
        // id 와 host/ts 를 다 알아도 열리면 안 된다(존재 은닉).
        String[] a = signup("a-eviso@edrdog.com");
        String[] b = signup("b-eviso@edrdog.com");
        seedEvent(b[1], "hostB", 10_000L, "evil.exe", 4321);
        String bId = listedIds(b[0]).get(0);

        mvc.perform(get("/api/events/" + bId)
                        .param("host", "hostB").param("ts", "10000")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isNotFound());
    }

    @Test
    void host_가_없으면_400() throws Exception {
        // host 없이 선택으로 두면 전체 스캔으로 흐르거나 조용히 못 찾는다.
        String[] a = signup("a-evnohost@edrdog.com");

        mvc.perform(get("/api/events/00000000-0000-0000-0000-000000000000")
                        .param("ts", "10000")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isBadRequest());
        mvc.perform(get("/api/events/00000000-0000-0000-0000-000000000000")
                        .param("host", "   ").param("ts", "10000")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isBadRequest());
    }

    @Test
    void ts_가_없으면_400() throws Exception {
        String[] a = signup("a-evnots@edrdog.com");

        mvc.perform(get("/api/events/00000000-0000-0000-0000-000000000000")
                        .param("host", "hostA")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isBadRequest());
    }

    @Test
    void 토큰_없으면_401() throws Exception {
        mvc.perform(get("/api/events/00000000-0000-0000-0000-000000000000")
                        .param("host", "hostA").param("ts", "10000"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void 단건_경로가_요약_경로를_가로채지_않는다() throws Exception {
        // /api/events/{id} 와 /api/events/summary 는 같은 자리다. summary 가 id 로 먹히면 요약이 죽는다.
        String[] a = signup("a-evsummary@edrdog.com");

        mvc.perform(get("/api/events/summary").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.total").value(0));
    }
}
