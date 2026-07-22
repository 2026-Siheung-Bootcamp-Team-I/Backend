package com.edrdog.apiservice.tenant;

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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * tenant webhook 등록/조회 배선 검증. H2(replace=ANY)로 부팅.
 * /api/tenant, /api/internal 은 X-API-Key 가 필요(ApiKeyPolicy 예외 아님). 기본 키 dev-api-key.
 */
@SpringBootTest
@AutoConfigureMockMvc
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.ANY)
class TenantWebhookIntegrationTest {

    private static final String API_KEY = "dev-api-key";
    private static final String INTERNAL_KEY = "dev-internal-key";

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper om;

    private static String signupJson(String email) {
        return "{\"email\":\"" + email + "\",\"password\":\"password1\"}";
    }

    private String signupAndToken(String email) throws Exception {
        MvcResult r = mvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(signupJson(email)))
                .andExpect(status().isCreated())
                .andReturn();
        return om.readTree(r.getResponse().getContentAsString()).get("token").asText();
    }

    private long tenantIdOf(String token) throws Exception {
        MvcResult me = mvc.perform(get("/api/auth/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andReturn();
        return om.readTree(me.getResponse().getContentAsString()).get("tenantId").asLong();
    }

    @Test
    void webhook_등록후_내부조회로_확인() throws Exception {
        String token = signupAndToken("hook@edrdog.com");
        long tenantId = tenantIdOf(token);
        String url = "https://hooks.slack.com/services/T000/B000/xxx";

        mvc.perform(put("/api/tenant/webhook")
                        .header("Authorization", "Bearer " + token)
                        .header("X-API-Key", API_KEY)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"webhookUrl\":\"" + url + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tenantId").value(tenantId))
                .andExpect(jsonPath("$.webhookUrl").value(url));

        mvc.perform(get("/api/internal/tenants/" + tenantId + "/webhook")
                        .header("X-Internal-Key", INTERNAL_KEY))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tenantId").value(tenantId))
                .andExpect(jsonPath("$.webhookUrl").value(url));
    }

    @Test
    void 없는_tenant_내부조회는_404() throws Exception {
        mvc.perform(get("/api/internal/tenants/999999/webhook").header("X-Internal-Key", INTERNAL_KEY))
                .andExpect(status().isNotFound());
    }

    @Test
    void https_아닌_URL_등록은_400() throws Exception {
        String token = signupAndToken("badurl@edrdog.com");
        mvc.perform(put("/api/tenant/webhook")
                        .header("Authorization", "Bearer " + token)
                        .header("X-API-Key", API_KEY)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"webhookUrl\":\"http://insecure\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void 내부조회는_내부키_없으면_401() throws Exception {
        mvc.perform(get("/api/internal/tenants/1/webhook"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void 내부조회는_프론트_API키만으로는_401() throws Exception {
        // 프론트에 노출되는 X-API-Key 로는 내부 조회 불가 (tenant webhook 열거 방지)
        mvc.perform(get("/api/internal/tenants/1/webhook").header("X-API-Key", API_KEY))
                .andExpect(status().isUnauthorized());
    }
}
