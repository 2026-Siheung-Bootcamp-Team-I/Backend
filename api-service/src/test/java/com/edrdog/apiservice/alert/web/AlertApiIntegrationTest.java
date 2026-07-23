package com.edrdog.apiservice.alert.web;

import com.edrdog.apiservice.alert.AlertId;
import com.edrdog.apiservice.alert.AlertRecord;
import com.edrdog.apiservice.alert.AlertRepository;
import com.edrdog.apiservice.alert.AlertStatus;
import com.edrdog.apiservice.clickhouse.ClickHouseReader;
import com.edrdog.apiservice.query.ClickHouseQuery;
import com.fasterxml.jackson.databind.ObjectMapper;
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

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 전체 컨텍스트를 띄워 alert API 배선(JPA, 라우팅, Bearer tenant 격리, 예외 핸들러)을 검증한다.
 * 실 Kafka 브로커에 붙지 않도록 리스너 auto-startup 을 끄고, H2(replace=ANY)로 부팅한다.
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

    @Autowired
    private AlertRepository alerts;

    // lineage 는 ClickHouse 를 읽는다. 실 브로커에 붙지 않도록 reader 를 대체해 지정한 events 행을 돌려준다.
    @MockitoBean
    private ClickHouseReader reader;

    private static String signupBody(String email) {
        return "{\"email\":\"" + email + "\",\"password\":\"password1\"}";
    }

    /** 회원가입으로 토큰과 tenantId 를 받는다. */
    private String[] signup(String email) throws Exception {
        MvcResult res = mvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(signupBody(email)))
                .andExpect(status().isCreated())
                .andReturn();
        var node = om.readTree(res.getResponse().getContentAsString());
        return new String[]{node.get("token").asText(), node.get("tenantId").asText()};
    }

    private String seedAlert(String tenantId, String host, long ts) {
        String id = AlertId.of(tenantId, host, "RULE_A", ts);
        alerts.save(AlertRecord.open(id, tenantId, host, "RULE_A", "T1059",
                "HIGH", "notify", ts, List.of("m1"), Instant.now()));
        return id;
    }

    private void seedAlert(String tenantId, String host, String ruleId, String severity, long ts) {
        String id = AlertId.of(tenantId, host, ruleId, ts);
        alerts.save(AlertRecord.open(id, tenantId, host, ruleId, "T1059",
                severity, "notify", ts, List.of("m1"), Instant.now()));
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
                .andExpect(jsonPath("$[0].threatName").value("다운로드 후 실행"));
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
        when(reader.query(any(ClickHouseQuery.class))).thenReturn(List.of(
                procRow("child.exe", "root.exe"),
                netRow("child.exe", "10.0.0.9", 4444)));

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
        when(reader.query(any(ClickHouseQuery.class))).thenReturn(List.of());

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

    // --- summary ---

    @Test
    void summary_는_자기_tenant_것만_집계하고_severity_분포와_topThreats_를_돌려준다() throws Exception {
        String[] a = signup("a-alertsummary@edrdog.com");
        String[] b = signup("b-alertsummary@edrdog.com");
        // A: 악성코드 2건(DOWNLOAD_AND_EXECUTE CRITICAL/HIGH), 권한상승 1건(SUSPICIOUS_PROCESS_CHAIN HIGH)
        seedAlert(a[1], "hostA", "DOWNLOAD_AND_EXECUTE", "CRITICAL", 100L);
        seedAlert(a[1], "hostA", "DOWNLOAD_AND_EXECUTE", "HIGH", 110L);
        seedAlert(a[1], "hostA", "SUSPICIOUS_PROCESS_CHAIN", "HIGH", 120L);
        // B: 섞이면 안 되는 다른 tenant 데이터
        seedAlert(b[1], "hostB", "DOWNLOAD_AND_EXECUTE", "CRITICAL", 130L);

        mvc.perform(get("/api/alerts/summary").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.total").value(3))
                .andExpect(jsonPath("$.severity.critical").value(1))
                .andExpect(jsonPath("$.severity.high").value(2))
                .andExpect(jsonPath("$.severity.medium").value(0))
                .andExpect(jsonPath("$.topThreats.length()").value(2))
                .andExpect(jsonPath("$.topThreats[0].category").value("악성코드"))
                .andExpect(jsonPath("$.topThreats[0].count").value(2))
                .andExpect(jsonPath("$.topThreats[1].category").value("권한상승"))
                .andExpect(jsonPath("$.topThreats[1].count").value(1));
    }

    @Test
    void summary_는_기간_필터를_적용한다() throws Exception {
        String[] a = signup("a-summaryperiod@edrdog.com");
        seedAlert(a[1], "hostA", "DOWNLOAD_AND_EXECUTE", "CRITICAL", 100L);
        seedAlert(a[1], "hostA", "DOWNLOAD_AND_EXECUTE", "HIGH", 300L);

        mvc.perform(get("/api/alerts/summary")
                        .param("from", "200")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.total").value(1))
                .andExpect(jsonPath("$.severity.critical").value(0))
                .andExpect(jsonPath("$.severity.high").value(1));
    }

    @Test
    void summary_total_은_미매핑_severity_도_포함하고_동점_카테고리는_이름순() throws Exception {
        String[] a = signup("a-alertsummarytotal@edrdog.com");
        // 악성코드 1건(CRITICAL) + 기타 1건(미등록 ruleId, severity=null) → 동점(각 1)
        seedAlert(a[1], "hostA", "DOWNLOAD_AND_EXECUTE", "CRITICAL", 100L);
        seedAlert(a[1], "hostA", "UNKNOWN_RULE", null, 110L);

        mvc.perform(get("/api/alerts/summary").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                // null severity 는 어느 버킷에도 안 들어가지만 total 에는 포함(2)
                .andExpect(jsonPath("$.total").value(2))
                .andExpect(jsonPath("$.severity.critical").value(1))
                .andExpect(jsonPath("$.severity.high").value(0))
                .andExpect(jsonPath("$.severity.medium").value(0))
                // 동점(각 1)은 category 오름차순으로 결정적: "기타"(ㄱ) < "악성코드"(ㅇ)
                .andExpect(jsonPath("$.topThreats.length()").value(2))
                .andExpect(jsonPath("$.topThreats[0].category").value("기타"))
                .andExpect(jsonPath("$.topThreats[1].category").value("악성코드"));
    }

    @Test
    void summary_토큰_없으면_401() throws Exception {
        mvc.perform(get("/api/alerts/summary")).andExpect(status().isUnauthorized());
    }
}
