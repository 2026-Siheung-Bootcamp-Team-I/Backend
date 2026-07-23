package com.edrdog.apiservice.host.web;

import com.edrdog.apiservice.alert.AlertId;
import com.edrdog.apiservice.alert.AlertRecord;
import com.edrdog.apiservice.alert.AlertRepository;
import com.edrdog.apiservice.clickhouse.ClickHouseReader;
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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 전체 컨텍스트로 hosts API 배선(라우팅, Bearer tenant 격리, events+alerts 병합)을 검증한다.
 * ClickHouse(events)는 실제 붙지 않도록 ClickHouseReader 를 목으로 대체하고, alert 는 H2 로 실적재한다.
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

    @Autowired
    private AlertRepository alerts;

    @MockitoBean
    private ClickHouseReader reader;

    /** 회원가입으로 토큰과 tenantId 를 받는다. */
    private String[] signup(String email) throws Exception {
        MvcResult res = mvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"password1\"}"))
                .andExpect(status().isCreated())
                .andReturn();
        var node = om.readTree(res.getResponse().getContentAsString());
        return new String[]{node.get("token").asText(), node.get("tenantId").asText()};
    }

    private void seedOpenAlert(String tenantId, String host, String severity, long ts) {
        String id = AlertId.of(tenantId, host, "RULE_" + ts, ts);
        alerts.save(AlertRecord.open(id, tenantId, host, "RULE_" + ts, "T1059",
                severity, "notify", ts, List.of("m1"), Instant.now()));
    }

    /** events 관측 호스트는 목으로 고정: h1, h2. */
    private void stubHosts() {
        when(reader.query(any())).thenReturn(List.of(
                Map.of("host", "h1", "last_seen", "2000"),
                Map.of("host", "h2", "last_seen", "1000")));
    }

    @Test
    void 목록은_events호스트에_자기_tenant_alert만_붙인다() throws Exception {
        stubHosts();
        String[] a = signup("a-hosts@edrdog.com");
        String[] b = signup("b-hosts@edrdog.com");
        seedOpenAlert(a[1], "h1", "CRITICAL", 100L);   // A 의 h1 은 위험
        seedOpenAlert(b[1], "h2", "CRITICAL", 200L);   // B 의 h2 (A 에는 안 보여야 함)

        mvc.perform(get("/api/hosts").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2))
                .andExpect(jsonPath("$[0].host").value("h1"))
                .andExpect(jsonPath("$[0].status").value("critical"))
                .andExpect(jsonPath("$[0].threats").value(1))
                .andExpect(jsonPath("$[0].lastSeen").value(2000))
                .andExpect(jsonPath("$[1].host").value("h2"))
                .andExpect(jsonPath("$[1].status").value("healthy"))  // B 의 alert 는 격리
                .andExpect(jsonPath("$[1].threats").value(0));
    }

    @Test
    void 요약은_status별_수와_총수를_준다() throws Exception {
        stubHosts();
        String[] a = signup("a-summary@edrdog.com");
        seedOpenAlert(a[1], "h1", "HIGH", 100L);   // h1 주의, h2 정상

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
    }
}
