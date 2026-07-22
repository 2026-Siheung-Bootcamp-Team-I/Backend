package com.edrdog.apiservice.alert.web;

import com.edrdog.apiservice.alert.AlertId;
import com.edrdog.apiservice.alert.AlertRecord;
import com.edrdog.apiservice.alert.AlertRepository;
import com.edrdog.apiservice.alert.AlertStatus;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Instant;
import java.util.List;

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

    @Test
    void 목록은_자기_tenant_것만_보인다() throws Exception {
        String[] a = signup("a-list@edrdog.com");
        String[] b = signup("b-list@edrdog.com");
        seedAlert(a[1], "hostA", 100L);
        seedAlert(b[1], "hostB", 200L);

        mvc.perform(get("/api/alerts").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].host").value("hostA"));
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
}
