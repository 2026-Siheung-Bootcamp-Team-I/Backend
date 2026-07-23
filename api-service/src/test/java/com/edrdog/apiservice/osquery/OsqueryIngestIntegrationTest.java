package com.edrdog.apiservice.osquery;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * osquery 수집 3종(enroll/config/log) 배선 검증. H2(replace=ANY)로 부팅.
 * events-raw 발행은 Kafka 없이 확인하려고 EventsRawProducer 를 목으로 대체하고 호출 인자를 검증한다.
 * /api/osquery/** 는 자체 인증(enroll_secret/node_key)이라 X-API-Key 없이 접근된다(ApiKeyPolicy 예외).
 */
@SpringBootTest
@AutoConfigureMockMvc
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.ANY)
@TestPropertySource(properties = "spring.kafka.listener.auto-startup=false")
class OsqueryIngestIntegrationTest {

    private static final String API_KEY = "dev-api-key";

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper om;

    @MockitoBean
    private EventsRawProducer producer;   // Kafka 대신 목: 발행 인자만 검증

    private String signupAndToken(String email) throws Exception {
        MvcResult r = mvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"password1\"}"))
                .andExpect(status().isCreated())
                .andReturn();
        return om.readTree(r.getResponse().getContentAsString()).get("token").asText();
    }

    private long tenantIdOf(String token) throws Exception {
        MvcResult me = mvc.perform(get("/api/auth/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk()).andReturn();
        return om.readTree(me.getResponse().getContentAsString()).get("tenantId").asLong();
    }

    /** 로그인 → enroll secret 발급 → 그 secret 반환. */
    private String issueEnrollSecret(String token) throws Exception {
        MvcResult r = mvc.perform(post("/api/tenant/enroll-secret")
                        .header("Authorization", "Bearer " + token)
                        .header("X-API-Key", API_KEY))
                .andExpect(status().isOk()).andReturn();
        return om.readTree(r.getResponse().getContentAsString()).get("enrollSecret").asText();
    }

    @Test
    void enroll_config_log_전체흐름_tenant_태깅_발행() throws Exception {
        String token = signupAndToken("node@edrdog.com");
        long tenantId = tenantIdOf(token);
        String secret = issueEnrollSecret(token);

        // enroll: 유효 secret → node_key 발급
        MvcResult enroll = mvc.perform(post("/api/osquery/enroll")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"enroll_secret\":\"" + secret + "\",\"host_identifier\":\"mac-001\",\"platform_type\":\"darwin\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.node_invalid").value(false))
                .andExpect(jsonPath("$.node_key").isNotEmpty())
                .andReturn();
        String nodeKey = om.readTree(enroll.getResponse().getContentAsString()).get("node_key").asText();

        // config: node_key 인증 → 수집 스케줄
        mvc.perform(post("/api/osquery/config")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"node_key\":\"" + nodeKey + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.node_invalid").value(false))
                .andExpect(jsonPath("$.schedule.process_events").exists())
                .andExpect(jsonPath("$.schedule.socket_events").exists());

        // log: result 로그 → tenant 태깅 후 events-raw 발행
        String logBody = "{\"node_key\":\"" + nodeKey + "\",\"log_type\":\"result\",\"data\":["
                + "{\"name\":\"process_events\",\"hostIdentifier\":\"mac-001\",\"unixTime\":\"1700000000\",\"action\":\"added\",\"columns\":{\"path\":\"/bin/bash\",\"parent\":\"zsh\"}}"
                + "]}";
        mvc.perform(post("/api/osquery/log")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(logBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.node_invalid").value(false));

        // events-raw 로 host 키 + tenantId 태깅된 원시 로그가 나갔는지
        ArgumentCaptor<String> host = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> raw = ArgumentCaptor.forClass(String.class);
        verify(producer, times(1)).publish(host.capture(), raw.capture());
        org.junit.jupiter.api.Assertions.assertEquals("mac-001", host.getValue());
        org.junit.jupiter.api.Assertions.assertEquals(
                String.valueOf(tenantId), om.readTree(raw.getValue()).get("tenantId").asText());
    }

    @Test
    void 잘못된_enroll_secret_은_node_invalid() throws Exception {
        mvc.perform(post("/api/osquery/enroll")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"enroll_secret\":\"nope\",\"host_identifier\":\"mac-x\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.node_invalid").value(true))
                .andExpect(jsonPath("$.node_key").doesNotExist());
    }

    @Test
    void 잘못된_node_key_log_는_발행하지_않고_node_invalid() throws Exception {
        mvc.perform(post("/api/osquery/log")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"node_key\":\"bogus\",\"log_type\":\"result\",\"data\":[{\"name\":\"process_events\",\"columns\":{}}]}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.node_invalid").value(true));

        verify(producer, never()).publish(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void 잘못된_node_key_config_는_node_invalid() throws Exception {
        mvc.perform(post("/api/osquery/config")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"node_key\":\"bogus\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.node_invalid").value(true));
    }
}
