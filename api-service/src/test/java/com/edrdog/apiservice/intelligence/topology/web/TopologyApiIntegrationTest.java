package com.edrdog.apiservice.intelligence.topology.web;

import com.edrdog.apiservice.clickhouse.ClickHouseReader;
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
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 전체 컨텍스트로 topology API 배선(라우팅, Bearer tenant 격리, events+alerts 집계 병합)을 검증한다.
 * ClickHouse 에는 붙지 않으므로 ClickHouseReader 를 목으로 대체하고 쿼리 종류별로 다른 행을 돌려준다
 * (집계 SQL 자체의 tenant 격리는 TopologyQueryBuilderTest 로 검증).
 */
@SpringBootTest
@AutoConfigureMockMvc
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.ANY)
@TestPropertySource(properties = "spring.kafka.listener.auto-startup=false")
class TopologyApiIntegrationTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper om;

    @MockitoBean
    private ClickHouseReader reader;

    private List<Map<String, Object>> relationRows = List.of();
    private List<Map<String, Object>> alertRows = List.of();
    private List<Map<String, Object>> riskRows = List.of();
    private String total = "0";
    private final List<ClickHouseQuery> queries = new ArrayList<>();

    @BeforeEach
    void routeReader() {
        relationRows = List.of(relation("h1", "api.example.co.kr", "domain", 12));
        alertRows = List.of();
        riskRows = List.of();
        total = "1";
        queries.clear();
        when(reader.query(any())).thenAnswer(inv -> {
            ClickHouseQuery q = inv.getArgument(0);
            queries.add(q);
            if (q.sql().contains("uniqExact")) {
                return List.of(Map.of("total", total));
            }
            if (q.sql().contains("countIf")) {
                return riskRows;
            }
            if (q.sql().contains("edrdog.alerts")) {
                return alertRows;
            }
            return relationRows;
        });
    }

    private static Map<String, Object> relation(String host, String dest, String destKind, long events) {
        return Map.of("host", host, "dest", dest, "destKind", destKind,
                "events", String.valueOf(events), "lastSeen", "1900",
                "protocols", List.of("tcp"), "l7Protocols", List.of("tls"));
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

    private ClickHouseQuery relationQuery() {
        return queries.stream()
                .filter(q -> q.sql().contains("GROUP BY host, dest, destKind"))
                .findFirst().orElseThrow();
    }

    @Test
    void 토큰_없으면_401() throws Exception {
        mvc.perform(get("/api/intelligence/topology")).andExpect(status().isUnauthorized());
    }

    @Test
    void 엔드포인트와_목적지_노드를_엣지로_이어_준다() throws Exception {
        String[] a = signup("a-topo@edrdog.com");
        riskRows = List.of(Map.of("host", "h1", "critical", "1", "high", "0", "medium", "0", "low", "0"));
        alertRows = List.of(Map.of("host", "h1", "dest", "api.example.co.kr", "alerts", "2"));

        mvc.perform(get("/api/intelligence/topology").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.edges.length()").value(1))
                .andExpect(jsonPath("$.edges[0].from").value("host:h1"))
                .andExpect(jsonPath("$.edges[0].to").value("dest:api.example.co.kr"))
                .andExpect(jsonPath("$.edges[0].events").value(12))
                .andExpect(jsonPath("$.edges[0].alerts").value(2))
                .andExpect(jsonPath("$.edges[0].protocols[0]").value("tcp"))
                .andExpect(jsonPath("$.edges[0].protocols[1]").value("tls"))
                .andExpect(jsonPath("$.nodes[?(@.id=='host:h1')].kind").value("endpoint"))
                .andExpect(jsonPath("$.nodes[?(@.id=='host:h1')].riskScore").value(25))
                .andExpect(jsonPath("$.nodes[?(@.id=='dest:api.example.co.kr')].destKind").value("domain"));
    }

    @Test
    void 조회는_로그인_유저의_tenant_로만_격리된다() throws Exception {
        String[] a = signup("a-topotenant@edrdog.com");

        mvc.perform(get("/api/intelligence/topology").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk());

        assertTrue(queries.size() >= 4, "관계/전체수/알림수/위험도 네 쿼리를 돈다");
        for (ClickHouseQuery q : queries) {
            assertEquals(a[1], q.params().get("tenant"), q.sql());
        }
    }

    @Test
    void 기간을_안_주면_최근_24시간을_본다() throws Exception {
        String[] a = signup("a-topowindow@edrdog.com");
        long before = System.currentTimeMillis();

        mvc.perform(get("/api/intelligence/topology").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk());

        ClickHouseQuery q = relationQuery();
        long from = Long.parseLong(q.params().get("from"));
        long to = Long.parseLong(q.params().get("to"));
        assertTrue(to >= before);
        assertEquals(24 * 60 * 60 * 1000L, to - from);
    }

    @Test
    void 기간_검색어_TopN_이_쿼리로_전달된다() throws Exception {
        String[] a = signup("a-topoparams@edrdog.com");

        mvc.perform(get("/api/intelligence/topology?from=1000&to=2000&q=example&limit=5")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk());

        ClickHouseQuery q = relationQuery();
        assertEquals("1000", q.params().get("from"));
        assertEquals("2000", q.params().get("to"));
        assertEquals("%example%", q.params().get("q"));
        assertTrue(q.sql().contains("LIMIT 5"), q.sql());
    }

    @Test
    void 잘렸으면_전체수와_함께_알린다() throws Exception {
        String[] a = signup("a-topotrunc@edrdog.com");
        total = "137";

        mvc.perform(get("/api/intelligence/topology?limit=1").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalRelations").value(137))
                .andExpect(jsonPath("$.shownRelations").value(1))
                .andExpect(jsonPath("$.truncated").value(true));
    }

    @Test
    void 관측이_없으면_빈_그래프_200() throws Exception {
        String[] a = signup("a-topoempty@edrdog.com");
        relationRows = List.of();
        total = "0";

        mvc.perform(get("/api/intelligence/topology").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.nodes.length()").value(0))
                .andExpect(jsonPath("$.edges.length()").value(0))
                .andExpect(jsonPath("$.truncated").value(false));
    }
}
