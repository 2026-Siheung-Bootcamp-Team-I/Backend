package com.edrdog.apiservice.operations.web;

import com.edrdog.apiservice.operations.ClickHouseIngestionInspector;
import com.edrdog.apiservice.operations.ClickHouseIngestionResult;
import com.edrdog.apiservice.operations.KafkaLagInspector;
import com.edrdog.apiservice.operations.KafkaTopicLagResult;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthEndpoint;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.HashSet;
import java.util.Set;

import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 전체 컨텍스트로 operations/health API 배선을 검증한다. 이 엔드포인트는 세션 Bearer 로만 인증하고
 * X-API-Key 는 요구하지 않는데(ApiKeyPolicy 의 /api/operations 예외), 그 배선이 실제로 동작하는지가
 * 이 테스트의 핵심이다.
 *
 * <p>Kafka(AdminClient)와 ClickHouse(ClickHouseReader)에는 실제로 붙을 수 없으므로, 그 둘을 감싸는
 * KafkaLagInspector/ClickHouseIngestionInspector 를 목으로 대체해 상태 조합(정상/실패/모름)을 그대로
 * 주입한다(TopologyApiIntegrationTest 가 ClickHouseReader 를 대체하는 것과 같은 방식).
 */
@SpringBootTest
@AutoConfigureMockMvc
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.ANY)
@TestPropertySource(properties = "spring.kafka.listener.auto-startup=false")
class OperationsHealthApiIntegrationTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper om;

    @MockitoBean
    private KafkaLagInspector kafkaLagInspector;

    @MockitoBean
    private ClickHouseIngestionInspector ingestionInspector;

    @MockitoBean
    private HealthEndpoint healthEndpoint;

    @BeforeEach
    void healthyByDefault() {
        // 기본은 전부 정상(up). 실패·모름 조합은 테스트별로 덮어쓴다.
        when(kafkaLagInspector.lag(anyString(), anyString()))
                .thenAnswer(inv -> KafkaTopicLagResult.of(inv.getArgument(0), inv.getArgument(1), 0L));
        when(ingestionInspector.check(anyString(), anyString()))
                .thenAnswer(inv -> ClickHouseIngestionResult.of(inv.getArgument(0), 0L, 10));
        when(healthEndpoint.healthForPath("db")).thenReturn(Health.up().build());
    }

    private String signup(String email) throws Exception {
        MvcResult res = mvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"password1\"}"))
                .andExpect(status().isCreated())
                .andReturn();
        return om.readTree(res.getResponse().getContentAsString()).get("token").asText();
    }

    @Test
    void 로그인한_유저는_세션_Bearer_만으로_200을_받는다() throws Exception {
        // X-API-Key 없이 세션 Bearer 만 보낸다 — /api/operations 예외가 ApiKeyPolicy 에서 빠지면
        // ApiKeyFilter 가 컨트롤러 진입 전에 401 로 막아 이 테스트가 깨진다.
        String token = signup("ops-bearer@edrdog.com");

        mvc.perform(get("/api/operations/health").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.dependencies[?(@.name=='kafka')].status").value("up"))
                .andExpect(jsonPath("$.dependencies[?(@.name=='clickhouse')].status").value("up"))
                .andExpect(jsonPath("$.dependencies[?(@.name=='mysql')].status").value("up"))
                .andExpect(jsonPath("$.checkedAt").isNumber());
    }

    @Test
    void 토큰_없으면_401() throws Exception {
        mvc.perform(get("/api/operations/health")).andExpect(status().isUnauthorized());
    }

    @Test
    void 잘못된_토큰이면_401() throws Exception {
        mvc.perform(get("/api/operations/health").header("Authorization", "Bearer invalid-token"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void 카프카_조회가_모두_실패해도_나머지_지표는_200으로_나온다() throws Exception {
        String token = signup("ops-kafkadown@edrdog.com");
        when(kafkaLagInspector.lag(anyString(), anyString()))
                .thenAnswer(inv -> KafkaTopicLagResult.error(inv.getArgument(0), inv.getArgument(1), "connection refused"));

        mvc.perform(get("/api/operations/health").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.kafkaLag[0].status").value("down"))
                .andExpect(jsonPath("$.kafkaLag[0].error").value("connection refused"))
                .andExpect(jsonPath("$.dependencies[?(@.name=='kafka')].status").value("down"))
                .andExpect(jsonPath("$.clickhouseIngestion[0].status").value("up"))
                .andExpect(jsonPath("$.dependencies[?(@.name=='clickhouse')].status").value("up"))
                .andExpect(jsonPath("$.dependencies[?(@.name=='mysql')].status").value("up"));
    }

    @Test
    void 랙을_못_구했을_때_0이_아니라_모름으로_나간다() throws Exception {
        String token = signup("ops-unknown@edrdog.com");
        // 커밋 이력이 없어 lag 을 못 구한 상태 — 0(안 밀림)과 구분되어야 한다.
        when(kafkaLagInspector.lag(anyString(), anyString()))
                .thenAnswer(inv -> KafkaTopicLagResult.of(inv.getArgument(0), inv.getArgument(1), null));
        // 테이블이 비어 지연 계산 기준 자체가 없는 상태.
        when(ingestionInspector.check(anyString(), anyString()))
                .thenAnswer(inv -> ClickHouseIngestionResult.of(inv.getArgument(0), null, 0));

        mvc.perform(get("/api/operations/health").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.kafkaLag[0].status").value("unknown"))
                .andExpect(jsonPath("$.kafkaLag[0].lag").value(nullValue()))
                .andExpect(jsonPath("$.clickhouseIngestion[0].status").value("unknown"))
                .andExpect(jsonPath("$.clickhouseIngestion[0].lagSeconds").value(nullValue()));
    }

    @Test
    void 응답에_특정_tenant의_관측값은_실리지_않는다() throws Exception {
        String token = signup("ops-notenant@edrdog.com");

        MvcResult res = mvc.perform(get("/api/operations/health").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andReturn();

        // 응답 필드가 정해진 집합을 벗어나지 않는지 확인한다 — host/도메인 등 tenant 관측값이 실릴 자리가 없어야 한다.
        JsonNode root = om.readTree(res.getResponse().getContentAsString());
        assertFieldsExactly(root, Set.of("kafkaLag", "clickhouseIngestion", "dependencies", "checkedAt"));
        for (JsonNode row : root.get("kafkaLag")) {
            assertFieldsExactly(row, Set.of("topic", "consumerGroup", "lag", "status", "error"));
        }
        for (JsonNode row : root.get("clickhouseIngestion")) {
            assertFieldsExactly(row, Set.of("table", "lagSeconds", "recentCount", "status", "error"));
        }
        for (JsonNode row : root.get("dependencies")) {
            assertFieldsExactly(row, Set.of("name", "status", "error"));
        }
    }

    private static void assertFieldsExactly(JsonNode node, Set<String> expected) {
        Set<String> actual = new HashSet<>();
        node.fieldNames().forEachRemaining(actual::add);
        assertEquals(expected, actual);
    }
}
