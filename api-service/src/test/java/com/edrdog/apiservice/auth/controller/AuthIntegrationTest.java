package com.edrdog.apiservice.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 전체 컨텍스트를 띄워 auth 배선(JPA 매핑, 컨트롤러 라우팅, 예외 핸들러, ApiKeyFilter 예외)을 검증한다.
 * 실제 Postgres 대신 H2(replace=ANY)로 부팅한다. 테스트 간 격리는 이메일을 다르게 써서 확보.
 */
@SpringBootTest
@AutoConfigureMockMvc
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.ANY)
class AuthIntegrationTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper om;

    private static String json(String email, String password) {
        return "{\"email\":\"" + email + "\",\"password\":\"" + password + "\"}";
    }

    @Test
    void 회원가입_내정보_로그아웃_전체흐름() throws Exception {
        MvcResult signup = mvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("flow@edrdog.com", "password1")))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.token").isNotEmpty())
                .andExpect(jsonPath("$.email").value("flow@edrdog.com"))
                .andExpect(jsonPath("$.role").value("admin"))
                .andExpect(jsonPath("$.tenantId").isNumber())
                .andReturn();
        String token = om.readTree(signup.getResponse().getContentAsString()).get("token").asText();

        mvc.perform(get("/api/auth/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("flow@edrdog.com"));

        mvc.perform(post("/api/auth/logout").header("Authorization", "Bearer " + token))
                .andExpect(status().isNoContent());

        // 로그아웃 후 같은 토큰은 무효
        mvc.perform(get("/api/auth/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void 토큰_없는_내정보는_401() throws Exception {
        mvc.perform(get("/api/auth/me")).andExpect(status().isUnauthorized());
    }

    @Test
    void 잘못된_비밀번호_로그인은_401() throws Exception {
        mvc.perform(post("/api/auth/signup").contentType(MediaType.APPLICATION_JSON)
                        .content(json("login@edrdog.com", "password1")))
                .andExpect(status().isCreated());
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(json("login@edrdog.com", "wrongpass1")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void 중복_이메일_회원가입은_409() throws Exception {
        String body = json("dup@edrdog.com", "password1");
        mvc.perform(post("/api/auth/signup").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isCreated());
        mvc.perform(post("/api/auth/signup").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isConflict());
    }

    @Test
    void auth_예외가_다른_api경로까지_열지_않는다() throws Exception {
        // /api/events 는 여전히 X-API-Key 가 필요 (ApiKeyFilter 작동)
        mvc.perform(get("/api/events")).andExpect(status().isUnauthorized());
    }
}
