package com.edrdog.apiservice.tenant.web;

import com.edrdog.apiservice.tenant.TenantService;
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
 * collector 가 에이전트 enroll 을 받을 때 쓰는 내부 API(/api/internal/agent/resolve-tenant) 배선 검증.
 * enroll secret 은 tenants 테이블(api-service 소유)에만 있으므로 collector 는 이 API 로만 tenant 를 안다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.ANY)
@TestPropertySource(properties = "spring.kafka.listener.auto-startup=false")
class InternalResolveTenantIntegrationTest {

    private static final String API_KEY = "dev-api-key";
    private static final String INTERNAL_KEY = "dev-internal-key";
    private static final String PATH = "/api/internal/agent/resolve-tenant";

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper om;

    private String signupAndToken(String email) throws Exception {
        MvcResult r = mvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"password1\"}"))
                .andExpect(status().isCreated())
                .andReturn();
        return om.readTree(r.getResponse().getContentAsString()).get("token").asText();
    }

    /** 조회 시점에 발급되므로(TenantService.getEnrollSecret) 대시보드가 한 번 읽는 것으로 준비된다. */
    private String[] issueEnrollSecret(String email) throws Exception {
        String token = signupAndToken(email);
        MvcResult r = mvc.perform(get("/api/tenant/enroll-secret")
                        .header("Authorization", "Bearer " + token)
                        .header("X-API-Key", API_KEY))
                .andExpect(status().isOk())
                .andReturn();
        var node = om.readTree(r.getResponse().getContentAsString());
        return new String[]{node.get("tenantId").asText(), node.get("enrollSecret").asText()};
    }

    private static String body(String secret) {
        return "{\"enrollSecret\":\"" + secret + "\"}";
    }

    @Test
    void 유효한_시크릿은_tenantId_를_돌려준다() throws Exception {
        String[] tenant = issueEnrollSecret("resolve-ok@edrdog.com");

        MvcResult r = mvc.perform(post(PATH)
                        .header("X-Internal-Key", INTERNAL_KEY)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body(tenant[1])))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tenantId").value(Long.parseLong(tenant[0])))
                .andReturn();

        assertEquals(Long.parseLong(tenant[0]),
                om.readTree(r.getResponse().getContentAsString()).get("tenantId").asLong());
    }

    @Test
    void 없는_시크릿은_404() throws Exception {
        mvc.perform(post(PATH)
                        .header("X-Internal-Key", INTERNAL_KEY)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("nope-not-a-secret")))
                .andExpect(status().isNotFound());
    }

    @Test
    void 빈_시크릿도_404() throws Exception {
        mvc.perform(post(PATH)
                        .header("X-Internal-Key", INTERNAL_KEY)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("")))
                .andExpect(status().isNotFound());
    }

    @Test
    void 내부키_없으면_401() throws Exception {
        String[] tenant = issueEnrollSecret("resolve-nokey@edrdog.com");

        mvc.perform(post(PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body(tenant[1])))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void 프론트_API키만으로는_401() throws Exception {
        // 프론트에 노출되는 X-API-Key 로 열리면 시크릿 대입으로 tenant 를 열거할 수 있다.
        String[] tenant = issueEnrollSecret("resolve-frontkey@edrdog.com");

        mvc.perform(post(PATH)
                        .header("X-API-Key", API_KEY)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body(tenant[1])))
                .andExpect(status().isUnauthorized());
    }
}
