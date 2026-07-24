package com.edrdog.apiservice.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 브라우저에서 다른 출처의 프론트가 API 를 호출할 수 있는지 검증한다.
 * 핵심은 preflight(OPTIONS)가 ApiKeyFilter 의 401 에 막히지 않고 CORS 헤더와 함께 통과하는 것이다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.ANY)
@TestPropertySource(properties = {
        "spring.kafka.listener.auto-startup=false",
        "edrdog.cors.allowed-origins=http://localhost:5173,https://edrdog.example"
})
class CorsIntegrationTest {

    @Autowired
    private MockMvc mvc;

    @Test
    void 허용된_출처의_preflight_는_인증_없이_통과한다() throws Exception {
        mvc.perform(options("/api/alerts")
                        .header("Origin", "http://localhost:5173")
                        .header("Access-Control-Request-Method", "GET")
                        .header("Access-Control-Request-Headers", "Authorization"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:5173"));
    }

    @Test
    void 설정에_적힌_다른_출처도_허용된다() throws Exception {
        mvc.perform(options("/api/alerts")
                        .header("Origin", "https://edrdog.example")
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", "https://edrdog.example"));
    }

    @Test
    void 트리아지에_쓰는_PATCH_도_preflight_에서_허용된다() throws Exception {
        mvc.perform(options("/api/alerts/some-id")
                        .header("Origin", "http://localhost:5173")
                        .header("Access-Control-Request-Method", "PATCH")
                        .header("Access-Control-Request-Headers", "Authorization,Content-Type"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Methods", org.hamcrest.Matchers.containsString("PATCH")));
    }

    @Test
    void 허용되지_않은_출처의_preflight_는_거부된다() throws Exception {
        mvc.perform(options("/api/alerts")
                        .header("Origin", "https://evil.example")
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(status().isForbidden());
    }

    @Test
    void 실제_요청_응답에도_허용_출처_헤더가_붙는다() throws Exception {
        // 토큰이 없어 401 이지만, 브라우저가 응답을 읽으려면 CORS 헤더는 붙어 있어야 한다.
        mvc.perform(get("/api/alerts").header("Origin", "http://localhost:5173"))
                .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:5173"));
    }
}
