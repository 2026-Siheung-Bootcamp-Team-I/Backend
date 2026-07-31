package com.edrdog.apiservice.alert.web;

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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * GET /api/alerts/rules 배선(세션 Bearer 인증, 카탈로그 전체 반환)을 검증한다.
 * tenant 격리가 없는 정적 데이터라 로그인 여부만 확인한다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.ANY)
@TestPropertySource(properties = "spring.kafka.listener.auto-startup=false")
class RuleCatalogControllerTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper om;

    private String signup(String email) throws Exception {
        MvcResult res = mvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"password1\"}"))
                .andExpect(status().isCreated())
                .andReturn();
        return om.readTree(res.getResponse().getContentAsString()).get("token").asText();
    }

    @Test
    void 로그인_유저는_룰_카탈로그_전체를_받는다() throws Exception {
        String token = signup("rule-catalog@edrdog.com");

        mvc.perform(get("/api/alerts/rules").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(4))
                .andExpect(jsonPath("$[0].ruleId").value("SUSPICIOUS_PROCESS_CHAIN"))
                .andExpect(jsonPath("$[0].threatName").value("의심스러운 프로세스 실행 체인"))
                .andExpect(jsonPath("$[0].category").value("권한상승"))
                .andExpect(jsonPath("$[0].mitre").value("T1059"))
                .andExpect(jsonPath("$[0].description").exists());
    }

    @Test
    void 토큰_없으면_401() throws Exception {
        mvc.perform(get("/api/alerts/rules")).andExpect(status().isUnauthorized());
    }

    @Test
    void 잘못된_토큰이면_401() throws Exception {
        mvc.perform(get("/api/alerts/rules").header("Authorization", "Bearer invalid-token"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void 응답_JSON_구조를_확인한다() throws Exception {
        String token = signup("rule-catalog-shape@edrdog.com");

        MvcResult res = mvc.perform(get("/api/alerts/rules").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andReturn();

        var root = om.readTree(res.getResponse().getContentAsString());
        assertEquals(4, root.size());
        var r2 = root.get(1);
        assertEquals("DOWNLOAD_AND_EXECUTE", r2.get("ruleId").asText());
        assertEquals("T1105+T1204", r2.get("mitre").asText());
    }
}
