package com.edrdog.apiservice.agent;

import com.edrdog.apiservice.responder.AgentCommand;
import com.edrdog.apiservice.responder.ResponderClient;
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

import java.util.List;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 에이전트 수집 4종(enroll/heartbeat/events/command-result) 배선 검증. H2(replace=ANY)로 부팅.
 * events-raw 발행은 Kafka 없이 확인하려고 EventsRawProducer 를 목으로 대체하고 호출 인자를 검증한다.
 * responder 도 목이다(하트비트가 대기 명령을 물어보므로 실제 HTTP 를 태우면 테스트가 responder 에 묶인다).
 * /api/agent/** 는 자체 인증(enroll_secret/node_key)이라 X-API-Key 없이 접근된다(ApiKeyPolicy 예외).
 */
@SpringBootTest
@AutoConfigureMockMvc
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.ANY)
@TestPropertySource(properties = "spring.kafka.listener.auto-startup=false")
class AgentIngestIntegrationTest {

    private static final String API_KEY = "dev-api-key";

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper om;

    @MockitoBean
    private EventsRawProducer producer;   // Kafka 대신 목: 발행 인자만 검증

    @MockitoBean
    private ResponderClient responder;    // 하트비트 명령 조회/결과 전달 대상

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

    private String issueEnrollSecret(String token) throws Exception {
        MvcResult r = mvc.perform(post("/api/tenant/enroll-secret")
                        .header("Authorization", "Bearer " + token)
                        .header("X-API-Key", API_KEY))
                .andExpect(status().isOk()).andReturn();
        return om.readTree(r.getResponse().getContentAsString()).get("enrollSecret").asText();
    }

    @Test
    void enroll_heartbeat_events_전체흐름_tenant_태깅_발행() throws Exception {
        String token = signupAndToken("node@edrdog.com");
        long tenantId = tenantIdOf(token);
        String secret = issueEnrollSecret(token);
        when(responder.pendingCommands("mac-001"))
                .thenReturn(List.of(new AgentCommand("cmd-1", "kill_process", "/tmp/evil.sh")));

        MvcResult enroll = mvc.perform(post("/api/agent/enroll")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"enroll_secret\":\"" + secret + "\",\"host_identifier\":\"mac-001\","
                                + "\"platform\":\"darwin\",\"agent_version\":\"0.1.0\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.node_key").isNotEmpty())
                .andReturn();
        String nodeKey = om.readTree(enroll.getResponse().getContentAsString()).get("node_key").asText();

        mvc.perform(post("/api/agent/heartbeat").header("X-Node-Key", nodeKey))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.config.sensors.process").value(true))
                .andExpect(jsonPath("$.config.flush_interval_seconds").value(5))
                .andExpect(jsonPath("$.config.watch_paths[0]").value("/Library/LaunchAgents"))
                .andExpect(jsonPath("$.commands[0].id").value("cmd-1"))
                .andExpect(jsonPath("$.commands[0].type").value("kill_process"));

        String body = """
                {"events":[
                  {"host":"mac-001","type":"process","ts":1785341400000,"process":"sh","parent":"bash","cmdline":"sh -c whoami"}
                ]}
                """;
        mvc.perform(post("/api/agent/events")
                        .header("X-Node-Key", nodeKey)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accepted").value(1));

        ArgumentCaptor<String> host = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> raw = ArgumentCaptor.forClass(String.class);
        verify(producer, times(1)).publish(host.capture(), raw.capture());
        org.junit.jupiter.api.Assertions.assertEquals("mac-001", host.getValue());
        org.junit.jupiter.api.Assertions.assertEquals(
                String.valueOf(tenantId), om.readTree(raw.getValue()).get("tenantId").asText());

        mvc.perform(post("/api/agent/command-result")
                        .header("X-Node-Key", nodeKey)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"command_id\":\"cmd-1\",\"status\":\"KILLED\",\"message\":\"pid 4242 종료\"}"))
                .andExpect(status().isOk());
        verify(responder, times(1)).reportCommandResult("cmd-1", "KILLED", "pid 4242 종료");
    }

    @Test
    void windows_는_시작프로그램_경로를_받는다() throws Exception {
        String token = signupAndToken("win@edrdog.com");
        String secret = issueEnrollSecret(token);
        MvcResult enroll = mvc.perform(post("/api/agent/enroll")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"enroll_secret\":\"" + secret + "\",\"host_identifier\":\"win-001\","
                                + "\"platform\":\"windows\",\"agent_version\":\"0.1.0\"}"))
                .andExpect(status().isOk()).andReturn();
        String nodeKey = om.readTree(enroll.getResponse().getContentAsString()).get("node_key").asText();

        mvc.perform(post("/api/agent/heartbeat").header("X-Node-Key", nodeKey))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.config.watch_paths[0]")
                        .value("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp"));
    }

    /** 실패를 200 본문에 담지 않는다. 에이전트는 401 을 보고 재등록한다. */
    @Test
    void 잘못된_enroll_secret_은_401() throws Exception {
        mvc.perform(post("/api/agent/enroll")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"enroll_secret\":\"nope\",\"host_identifier\":\"mac-x\",\"platform\":\"darwin\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_enroll_secret"));
    }

    @Test
    void 잘못된_node_key_events_는_발행하지_않고_401() throws Exception {
        mvc.perform(post("/api/agent/events")
                        .header("X-Node-Key", "bogus")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"events\":[{\"host\":\"mac-x\",\"type\":\"process\"}]}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_node_key"));

        verify(producer, never()).publish(anyString(), anyString());
    }

    @Test
    void node_key_없는_heartbeat_는_401() throws Exception {
        mvc.perform(post("/api/agent/heartbeat"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_node_key"));
    }

    @Test
    void 잘못된_node_key_command_result_는_401_이고_responder_로_넘기지_않는다() throws Exception {
        mvc.perform(post("/api/agent/command-result")
                        .header("X-Node-Key", "bogus")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"command_id\":\"cmd-1\",\"status\":\"KILLED\",\"message\":\"\"}"))
                .andExpect(status().isUnauthorized());

        verify(responder, never()).reportCommandResult(anyString(), anyString(), anyString());
    }
}
