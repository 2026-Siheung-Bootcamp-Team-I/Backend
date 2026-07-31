package com.edrdog.apiservice.host.web;

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
 * 전체 컨텍스트로 hosts API 배선(라우팅, Bearer tenant 격리, events+alert집계 병합)을 검증한다.
 * ClickHouse 는 실제로 붙지 않으므로 ClickHouseReader 를 목으로 대체하고, events 조회에는 관측 호스트를,
 * alerts 조회에는 host 별 열린 집계를 각각 돌려준다(집계 SQL 의 tenant 격리는 AlertQueryBuilderTest 로 검증).
 */
@SpringBootTest
@AutoConfigureMockMvc
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.ANY)
@TestPropertySource(properties = "spring.kafka.listener.auto-startup=false")
class HostApiIntegrationTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper om;

    @MockitoBean
    private ClickHouseReader reader;

    /** host 별 열린 alert 집계(alerts 테이블 조회 응답). 테스트마다 세팅한다. */
    private List<Map<String, Object>> countRows = List.of();
    /** host 별 열린 alert severity 분포(위험 점수 재료). 테스트마다 세팅한다. */
    private List<Map<String, Object>> severityRows = List.of();
    /** process-tree 재구성용 events 응답. 테스트마다 세팅한다. */
    private List<Map<String, Object>> lineageRows = List.of();
    /** 마지막 lineage 조회 쿼리(기간 파라미터 확인용). */
    private ClickHouseQuery lastLineageQuery;

    @BeforeEach
    void routeReader() {
        countRows = List.of();
        severityRows = List.of();
        lineageRows = List.of();
        lastLineageQuery = null;
        // 호스트 목록 조회는 관측 호스트 h1, h2 로 고정, alerts 집계는 countRows/severityRows, lineage 조회는 lineageRows.
        when(reader.query(any())).thenAnswer(inv -> {
            ClickHouseQuery q = inv.getArgument(0);
            if (q.sql().contains("edrdog.alerts")) {
                return q.sql().contains("AS critical") ? severityRows : countRows;
            }
            if (!q.sql().contains("GROUP BY host")) {
                lastLineageQuery = q;
                return lineageRows;
            }
            return List.of(
                    Map.of("host", "h1", "last_seen", "2000"),
                    Map.of("host", "h2", "last_seen", "1000"));
        });
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

    private static Map<String, Object> count(String host, long total, long critical, long high) {
        return Map.of("host", host, "openTotal", String.valueOf(total),
                "openCritical", String.valueOf(critical), "openHigh", String.valueOf(high));
    }

    private static Map<String, Object> severity(String host, long critical, long high, long medium, long low) {
        return Map.of("host", host, "critical", String.valueOf(critical), "high", String.valueOf(high),
                "medium", String.valueOf(medium), "low", String.valueOf(low));
    }

    @Test
    void 목록은_events호스트에_열린_alert집계를_붙인다() throws Exception {
        String[] a = signup("a-hosts@edrdog.com");
        countRows = List.of(count("h1", 1, 1, 0));   // h1 은 위험(CRITICAL), h2 는 집계 없음
        severityRows = List.of(severity("h1", 1, 0, 0, 0));

        mvc.perform(get("/api/hosts").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2))
                .andExpect(jsonPath("$[0].host").value("h1"))
                .andExpect(jsonPath("$[0].status").value("critical"))
                .andExpect(jsonPath("$[0].threats").value(1))
                .andExpect(jsonPath("$[0].lastSeen").value(2000))
                .andExpect(jsonPath("$[1].host").value("h2"))
                .andExpect(jsonPath("$[1].status").value("healthy"))
                .andExpect(jsonPath("$[1].threats").value(0));
    }

    @Test
    void 목록은_토폴로지와_같은_기준의_위험점수를_함께_준다() throws Exception {
        String[] a = signup("a-risk@edrdog.com");
        severityRows = List.of(severity("h1", 1, 2, 0, 0));

        // CRITICAL 1 + HIGH 2 = 25 + 20. 토폴로지 엔드포인트 노드와 같은 RiskScore 를 쓴다.
        mvc.perform(get("/api/hosts").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].host").value("h1"))
                .andExpect(jsonPath("$[0].riskScore").value(45))
                .andExpect(jsonPath("$[1].host").value("h2"))
                .andExpect(jsonPath("$[1].riskScore").value(0));
    }

    @Test
    void 요약은_status별_수와_총수를_준다() throws Exception {
        String[] a = signup("a-summary@edrdog.com");
        countRows = List.of(count("h1", 1, 0, 1));   // h1 주의(HIGH), h2 정상

        mvc.perform(get("/api/hosts/summary").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.healthy").value(1))
                .andExpect(jsonPath("$.warning").value(1))
                .andExpect(jsonPath("$.critical").value(0))
                .andExpect(jsonPath("$.total").value(2));
    }

    @Test
    void 토큰_없으면_401() throws Exception {
        mvc.perform(get("/api/hosts")).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/hosts/summary")).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/hosts/h1/process-tree")).andExpect(status().isUnauthorized());
    }

    // --- process-tree (엔드포인트 기준 계보) ---

    @Test
    void process_tree_는_alert_lineage_와_같은_그래프_형태를_준다() throws Exception {
        String[] a = signup("a-tree@edrdog.com");
        lineageRows = List.of(
                Map.of("type", "process", "ts", 100L, "process", "child.exe", "parent", "root.exe",
                        "dest_ip", "", "dest_port", 0),
                Map.of("type", "network", "ts", 200L, "process", "child.exe", "parent", "",
                        "dest_ip", "10.0.0.9", "dest_port", 4444));

        mvc.perform(get("/api/hosts/h1/process-tree").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.nodes.length()").value(3))
                .andExpect(jsonPath("$.edges.length()").value(2))
                .andExpect(jsonPath("$.edges[?(@.rel=='spawned')].from").value("proc:root.exe"))
                .andExpect(jsonPath("$.edges[?(@.rel=='connected')].to").value("net:10.0.0.9:4444"));
    }

    @Test
    void process_tree_는_tenant와_host로_격리해서_조회한다() throws Exception {
        String[] a = signup("a-treescope@edrdog.com");

        mvc.perform(get("/api/hosts/h1/process-tree?from=1000&to=2000")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk());

        assertEquals(a[1], lastLineageQuery.params().get("tenant"));
        assertEquals("h1", lastLineageQuery.params().get("host"));
        assertEquals("1000", lastLineageQuery.params().get("from"));
        assertEquals("2000", lastLineageQuery.params().get("to"));
    }

    @Test
    void process_tree_는_기간_없으면_최근_24시간을_본다() throws Exception {
        String[] a = signup("a-treewindow@edrdog.com");
        long before = System.currentTimeMillis();

        mvc.perform(get("/api/hosts/h1/process-tree").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk());

        long from = Long.parseLong(lastLineageQuery.params().get("from"));
        long to = Long.parseLong(lastLineageQuery.params().get("to"));
        assertTrue(to >= before);
        assertEquals(24 * 60 * 60 * 1000L, to - from);
    }

    @Test
    void 이벤트가_없으면_process_tree_는_빈_그래프_200() throws Exception {
        String[] a = signup("a-emptytree@edrdog.com");
        lineageRows = List.of();

        mvc.perform(get("/api/hosts/h1/process-tree").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.nodes.length()").value(0))
                .andExpect(jsonPath("$.edges.length()").value(0));
    }
}
