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

    @BeforeEach
    void routeReader() {
        countRows = List.of();
        // events 조회는 관측 호스트 h1, h2 로 고정, alerts 조회는 countRows 로 돌려준다.
        when(reader.query(any())).thenAnswer(inv -> {
            ClickHouseQuery q = inv.getArgument(0);
            if (q.sql().contains("edrdog.alerts")) {
                return countRows;
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

    @Test
    void 목록은_events호스트에_열린_alert집계를_붙인다() throws Exception {
        String[] a = signup("a-hosts@edrdog.com");
        countRows = List.of(count("h1", 1, 1, 0));   // h1 은 위험(CRITICAL), h2 는 집계 없음

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
    }
}
