package com.edrdog.collectorservice.agent;

import com.edrdog.collectorservice.agent.repository.AgentNodeRepository;
import com.edrdog.schema.Event;
import com.edrdog.collectorservice.responder.AgentCommand;
import com.edrdog.collectorservice.responder.ResponderClient;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
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
 * 수집 4종(enroll/heartbeat/events/command-result)과 내부 노드 조회 배선 검증. H2(replace=ANY)로 부팅.
 * events 발행은 Kafka 없이 확인하려고 EventsProducer 를 목으로 대체하고 호출 인자를 검증한다.
 * enroll secret 검증(api-service)과 responder 도 목이다. 실제 HTTP 를 태우면 이 테스트가 그 서비스에 묶인다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.ANY)
class AgentIngestIntegrationTest {

    private static final String SECRET = "tenant-7-secret";
    private static final String INTERNAL_KEY = "dev-internal-key";

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper om;

    @Autowired
    private AgentNodeRepository nodes;

    @MockitoBean
    private EventsProducer producer;          // Kafka 대신 목: 발행 인자만 검증

    @MockitoBean
    private TenantResolverClient tenants;     // api-service 대신 목: enroll secret → tenant

    @MockitoBean
    private ResponderClient responder;        // 하트비트 명령 조회/결과 전달 대상

    private String enroll(String host, String platform) throws Exception {
        when(tenants.resolve(SECRET)).thenReturn(Optional.of(7L));
        MvcResult r = mvc.perform(post("/api/agent/enroll")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"enroll_secret\":\"" + SECRET + "\",\"host_identifier\":\"" + host + "\","
                                + "\"platform\":\"" + platform + "\",\"agent_version\":\"0.1.0\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.node_key").isNotEmpty())
                .andReturn();
        return om.readTree(r.getResponse().getContentAsString()).get("node_key").asText();
    }

    @Test
    void enroll_heartbeat_events_전체흐름_tenant_태깅_발행() throws Exception {
        when(producer.publish(any(Event.class))).thenReturn(true);
        when(responder.pendingCommands("mac-001"))
                .thenReturn(List.of(new AgentCommand("cmd-1", "kill_process", "/tmp/evil.sh")));
        String nodeKey = enroll("mac-001", "darwin");

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

        ArgumentCaptor<Event> published = ArgumentCaptor.forClass(Event.class);
        verify(producer, times(1)).publish(published.capture());
        assertEquals("mac-001", published.getValue().getHost());
        assertEquals("7", published.getValue().getTenantId());
        assertEquals("sh", published.getValue().getProcess());

        mvc.perform(post("/api/agent/command-result")
                        .header("X-Node-Key", nodeKey)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"command_id\":\"cmd-1\",\"status\":\"KILLED\",\"message\":\"pid 4242 종료\"}"))
                .andExpect(status().isOk());
        verify(responder, times(1)).reportCommandResult("cmd-1", "KILLED", "pid 4242 종료");
    }

    /** 검증에서 걸린 건은 발행하지 않고 accepted 에서도 빠진다(에이전트가 배치를 지워도 무방한 건수여야 한다). */
    @Test
    void 검증_실패_이벤트는_발행하지_않는다() throws Exception {
        when(producer.publish(any(Event.class))).thenReturn(true);
        String nodeKey = enroll("mac-002", "darwin");

        String body = """
                {"events":[
                  {"host":"mac-002","type":"process","ts":1785341400000,"process":"sh"},
                  {"host":"mac-002","type":"process","ts":1785341400},
                  {"host":"","type":"process","ts":1785341400000},
                  {"host":"mac-002","type":"모르는타입","ts":1785341400000},
                  {"host":"mac-002","type":"network","ts":1785341400000}
                ]}
                """;
        mvc.perform(post("/api/agent/events")
                        .header("X-Node-Key", nodeKey)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accepted").value(1));

        verify(producer, times(1)).publish(any(Event.class));
    }

    @Test
    void windows_는_시작프로그램_경로를_받는다() throws Exception {
        String nodeKey = enroll("win-001", "windows");

        mvc.perform(post("/api/agent/heartbeat").header("X-Node-Key", nodeKey))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.config.watch_paths[0]")
                        .value("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp"));
    }

    /** DB 가 새도 그 값으로 위장할 수 없어야 한다. 저장된 건 해시뿐이고 인증은 평문을 해시해서 한다. */
    @Test
    void node_key_는_평문이_아니라_해시로_저장된다() throws Exception {
        String nodeKey = enroll("mac-003", "darwin");

        assertTrue(nodes.findById(nodeKey).isEmpty());
        assertTrue(nodes.findById(Tokens.hash(nodeKey)).isPresent());
        assertFalse(nodes.findAll().stream().anyMatch(n -> n.getNodeKeyHash().equals(nodeKey)));

        mvc.perform(post("/api/agent/heartbeat").header("X-Node-Key", nodeKey))
                .andExpect(status().isOk());
    }

    /** 평문을 저장하지 않아 기존 토큰을 되돌려줄 수 없다. 재-enroll 은 새 토큰을 발급하고 노드는 하나로 유지한다. */
    @Test
    void 재_enroll_은_새_토큰을_발급하고_노드를_하나로_유지한다() throws Exception {
        String first = enroll("mac-004", "darwin");
        String second = enroll("mac-004", "darwin");

        org.junit.jupiter.api.Assertions.assertNotEquals(first, second);
        assertEquals(1, nodes.findByTenantId(7L).stream()
                .filter(n -> n.getHostIdentifier().equals("mac-004")).count());
        assertTrue(nodes.findById(Tokens.hash(first)).isEmpty());

        mvc.perform(post("/api/agent/heartbeat").header("X-Node-Key", first))
                .andExpect(status().isUnauthorized());
        mvc.perform(post("/api/agent/heartbeat").header("X-Node-Key", second))
                .andExpect(status().isOk());
    }

    /** 실패를 200 본문에 담지 않는다. 에이전트는 401 을 보고 재등록한다. */
    @Test
    void 잘못된_enroll_secret_은_401() throws Exception {
        when(tenants.resolve("nope")).thenReturn(Optional.empty());

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

        verify(producer, never()).publish(any(Event.class));
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

    @Test
    void 내부_노드_조회는_등록_노드를_epoch_millis_로_돌려준다() throws Exception {
        enroll("mac-005", "darwin");

        mvc.perform(get("/api/internal/nodes").param("tenantId", "7").header("X-Internal-Key", INTERNAL_KEY))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.host=='mac-005')].platform").value("darwin"))
                .andExpect(jsonPath("$[?(@.host=='mac-005')].lastSeenAt").isNotEmpty());
    }

    @Test
    void 내부_키가_틀리거나_없으면_401() throws Exception {
        mvc.perform(get("/api/internal/nodes").param("tenantId", "7").header("X-Internal-Key", "wrong"))
                .andExpect(status().isUnauthorized());
        mvc.perform(get("/api/internal/nodes").param("tenantId", "7"))
                .andExpect(status().isUnauthorized());
    }

    /** 호출자 실수로 500 을 내면 호스트 목록 화면 전체가 죽는다. */
    @Test
    void 숫자가_아닌_tenantId_는_빈_배열() throws Exception {
        mvc.perform(get("/api/internal/nodes").param("tenantId", "abc").header("X-Internal-Key", INTERNAL_KEY))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isEmpty());
    }
}
