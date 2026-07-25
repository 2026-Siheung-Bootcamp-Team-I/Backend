package com.edrdog.apiservice.alert.web;

import com.edrdog.apiservice.alert.AlertId;
import com.edrdog.apiservice.alert.AlertStatus;
import com.edrdog.apiservice.clickhouse.ClickHouseReader;
import com.edrdog.apiservice.query.ClickHouseQuery;
import com.edrdog.apiservice.responder.KillResult;
import com.edrdog.apiservice.responder.ResponderClient;
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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 전체 컨텍스트로 alert API 배선(라우팅, Bearer tenant 격리, ClickHouse 읽기 + 오버레이(MySQL) 병합, 예외)을 검증한다.
 * 판정기록(ClickHouse)은 실제로 붙지 않으므로 ClickHouseReader 를 목으로 대체하고, 목이 alerts 테이블 조회에는
 * 시드 판정기록을, events 조회에는 lineage 이벤트를 돌려준다(tenant/id 는 쿼리 파라미터로 걸러 격리를 반영).
 * 오버레이 status 는 H2 로 실제 upsert 된다. 집계(summary/timeseries)는 CH GROUP BY 라 여기서 못 돌리며,
 * SQL 은 AlertQueryBuilderTest, 조립 로직은 AlertServiceTest 로 검증한다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.ANY)
@TestPropertySource(properties = "spring.kafka.listener.auto-startup=false")
class AlertApiIntegrationTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper om;

    @MockitoBean
    private ClickHouseReader reader;

    @MockitoBean
    private ResponderClient responder;

    /** 목 ClickHouse 의 판정기록(alerts 테이블) 시드. tenant/id 필터는 목이 쿼리 파라미터로 반영한다. */
    private final List<Map<String, Object>> alertRows = new ArrayList<>();
    /** 목 ClickHouse 의 events(lineage) 응답. */
    private List<Map<String, Object>> eventRows = List.of();

    @BeforeEach
    void routeReader() {
        alertRows.clear();
        eventRows = List.of();
        when(reader.query(any())).thenAnswer(inv -> {
            ClickHouseQuery q = inv.getArgument(0);
            if (q.sql().contains("edrdog.events")) {
                return eventRows;
            }
            String tenant = q.params().get("tenant");
            return alertRows.stream()
                    .filter(r -> tenant.equals(r.get("tenant_id")))
                    .filter(r -> !q.params().containsKey("id") || q.params().get("id").equals(r.get("id")))
                    .toList();
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

    /** 판정기록 한 건을 목 ClickHouse 에 시드한다(ts 는 CH UInt64 처럼 문자열). */
    private String seedAlert(String tenantId, String host, String ruleId, String severity, long ts) {
        String id = AlertId.of(tenantId, host, ruleId, ts);
        alertRows.add(new java.util.HashMap<>(Map.of(
                "id", id, "tenant_id", tenantId, "host", host, "rule_id", ruleId,
                "mitre", "T1059", "severity", severity == null ? "" : severity, "action", "notify",
                "ts", String.valueOf(ts), "matched", List.of("m1"))));
        return id;
    }

    private String seedAlert(String tenantId, String host, long ts) {
        return seedAlert(tenantId, host, "RULE_A", "HIGH", ts);
    }

    @Test
    void 목록은_자기_tenant_것만_보인다() throws Exception {
        String[] a = signup("a-list@edrdog.com");
        String[] b = signup("b-list@edrdog.com");
        seedAlert(a[1], "hostA", "DOWNLOAD_AND_EXECUTE", "HIGH", 100L);
        seedAlert(b[1], "hostB", 200L);

        mvc.perform(get("/api/alerts").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].host").value("hostA"))
                .andExpect(jsonPath("$[0].ruleId").value("DOWNLOAD_AND_EXECUTE"))
                .andExpect(jsonPath("$[0].threatName").value("다운로드 후 실행"))
                .andExpect(jsonPath("$[0].status").value("open"));
    }

    @Test
    void 남의_alert_상세는_404() throws Exception {
        String[] a = signup("a-detail@edrdog.com");
        String[] b = signup("b-detail@edrdog.com");
        String bId = seedAlert(b[1], "hostB", 200L);

        mvc.perform(get("/api/alerts/" + bId).header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isNotFound());
    }

    @Test
    void 자기_alert_트리아지는_200_잘못된_status_400() throws Exception {
        String[] a = signup("a-triage@edrdog.com");
        String id = seedAlert(a[1], "hostA", 100L);

        mvc.perform(patch("/api/alerts/" + id).header("Authorization", "Bearer " + a[0])
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"status\":\"" + AlertStatus.CONFIRMED + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(AlertStatus.CONFIRMED));

        // 오버레이가 실제로 반영됐는지 상세로 재확인
        mvc.perform(get("/api/alerts/" + id).header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(AlertStatus.CONFIRMED));

        mvc.perform(patch("/api/alerts/" + id).header("Authorization", "Bearer " + a[0])
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"status\":\"deleted\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void 남의_alert_트리아지는_404() throws Exception {
        String[] a = signup("a-ptriage@edrdog.com");
        String[] b = signup("b-ptriage@edrdog.com");
        String bId = seedAlert(b[1], "hostB", 200L);

        mvc.perform(patch("/api/alerts/" + bId).header("Authorization", "Bearer " + a[0])
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"status\":\"" + AlertStatus.CONFIRMED + "\"}"))
                .andExpect(status().isNotFound());
    }

    @Test
    void 토큰_없으면_401() throws Exception {
        mvc.perform(get("/api/alerts")).andExpect(status().isUnauthorized());
    }

    // --- respond (kill 프록시) ---

    @Test
    void 자기_alert_respond_는_알림host로_responder에_위임한다() throws Exception {
        String[] a = signup("a-respond@edrdog.com");
        String id = seedAlert(a[1], "hostA", 100L);
        when(responder.kill(eq("hostA"), eq("evil.exe")))
                .thenReturn(new KillResult("hostA", "evil.exe", "KILLED", "exec-1"));

        mvc.perform(post("/api/alerts/" + id + "/respond").header("Authorization", "Bearer " + a[0])
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"target\":\"evil.exe\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.host").value("hostA"))
                .andExpect(jsonPath("$.status").value("KILLED"))
                .andExpect(jsonPath("$.executionId").value("exec-1"));

        // host 는 알림에서 오고 클라이언트 입력이 아님을 확인
        verify(responder).kill("hostA", "evil.exe");
    }

    @Test
    void 남의_alert_respond_는_404이고_responder를_호출하지_않는다() throws Exception {
        String[] a = signup("a-presp@edrdog.com");
        String[] b = signup("b-presp@edrdog.com");
        String bId = seedAlert(b[1], "hostB", 200L);

        mvc.perform(post("/api/alerts/" + bId + "/respond").header("Authorization", "Bearer " + a[0])
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"target\":\"evil.exe\"}"))
                .andExpect(status().isNotFound());

        verify(responder, never()).kill(any(), any());
    }

    @Test
    void respond_target_없으면_400() throws Exception {
        String[] a = signup("a-respnotarget@edrdog.com");
        String id = seedAlert(a[1], "hostA", 100L);

        mvc.perform(post("/api/alerts/" + id + "/respond").header("Authorization", "Bearer " + a[0])
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"target\":\"  \"}"))
                .andExpect(status().isBadRequest());

        verify(responder, never()).kill(any(), any());
    }

    @Test
    void respond_토큰_없으면_401() throws Exception {
        mvc.perform(post("/api/alerts/anything/respond")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"target\":\"evil.exe\"}"))
                .andExpect(status().isUnauthorized());

        verify(responder, never()).kill(any(), any());
    }

    // --- lineage ---

    private static Map<String, Object> procRow(String process, String parent) {
        return Map.of("type", "process", "ts", 100L, "process", process, "parent", parent,
                "dest_ip", "", "dest_port", 0);
    }

    private static Map<String, Object> netRow(String process, String ip, int port) {
        return Map.of("type", "network", "ts", 100L, "process", process, "parent", "",
                "dest_ip", ip, "dest_port", port);
    }

    @Test
    void 자기_alert_lineage_는_이름체인_그래프를_돌려준다() throws Exception {
        String[] a = signup("a-lineage@edrdog.com");
        String id = seedAlert(a[1], "hostA", 100L);
        eventRows = List.of(procRow("child.exe", "root.exe"), netRow("child.exe", "10.0.0.9", 4444));

        mvc.perform(get("/api/alerts/" + id + "/lineage").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.nodes.length()").value(3))
                .andExpect(jsonPath("$.edges.length()").value(2))
                .andExpect(jsonPath("$.edges[?(@.rel=='spawned')].from").value("proc:root.exe"))
                .andExpect(jsonPath("$.edges[?(@.rel=='connected')].to").value("net:10.0.0.9:4444"));
    }

    @Test
    void 이벤트가_없으면_lineage_는_빈_그래프_200() throws Exception {
        String[] a = signup("a-emptylineage@edrdog.com");
        String id = seedAlert(a[1], "hostA", 100L);
        eventRows = List.of();

        mvc.perform(get("/api/alerts/" + id + "/lineage").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.nodes.length()").value(0))
                .andExpect(jsonPath("$.edges.length()").value(0));
    }

    @Test
    void 남의_alert_lineage_는_404() throws Exception {
        String[] a = signup("a-plineage@edrdog.com");
        String[] b = signup("b-plineage@edrdog.com");
        String bId = seedAlert(b[1], "hostB", 200L);

        mvc.perform(get("/api/alerts/" + bId + "/lineage").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isNotFound());
    }

    @Test
    void lineage_도_토큰_없으면_401() throws Exception {
        mvc.perform(get("/api/alerts/anything/lineage")).andExpect(status().isUnauthorized());
    }

    @Test
    void summary_토큰_없으면_401() throws Exception {
        mvc.perform(get("/api/alerts/summary")).andExpect(status().isUnauthorized());
    }
}
