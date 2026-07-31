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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
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
    void API키가_필요한_경로도_preflight_는_통과한다() throws Exception {
        // 브라우저 preflight 는 X-API-Key 를 안 실어서, 여기서 401 이면 본 요청이 안 나가 enroll secret 발급이 통째로 막힌다.
        mvc.perform(options("/api/tenant/enroll-secret")
                        .header("Origin", "http://localhost:5173")
                        .header("Access-Control-Request-Method", "POST")
                        .header("Access-Control-Request-Headers", "Authorization,X-API-Key"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:5173"));
    }

    @Test
    void preflight_가_아닌_OPTIONS_는_여전히_API키를_요구한다() throws Exception {
        // Origin/Access-Control-Request-Method 없는 OPTIONS 는 preflight 가 아니므로 그냥 막는다.
        mvc.perform(options("/api/tenant/enroll-secret"))
                .andExpect(status().isUnauthorized());
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

    @Test
    void 페이지네이션_헤더는_브라우저가_읽을_수_있게_노출된다() throws Exception {
        // 페이지 정보는 본문이 아니라 헤더로 나간다. exposedHeaders 에 없으면 브라우저가 아예 못 읽어서
        // 서버는 정상인데 화면에서만 값이 안 보이고, 그건 원인을 찾기 어렵다.
        var res = mvc.perform(get("/api/alerts").header("Origin", "http://localhost:5173"))
                .andExpect(header().exists("Access-Control-Expose-Headers"))
                .andReturn();
        String exposed = res.getResponse().getHeader("Access-Control-Expose-Headers");
        for (String name : com.edrdog.apiservice.web.PageHeaders.ALL) {
            org.junit.jupiter.api.Assertions.assertTrue(exposed.contains(name), name + " 가 " + exposed + " 에 없다");
        }
    }

    @Test
    void API키_거부_401_에도_허용_출처_헤더가_붙는다() throws Exception {
        // 헤더가 없으면 브라우저는 본문을 못 읽고 네트워크 오류로만 받는다. 그러면 화면에
        // "유효한 X-API-Key 가 필요합니다" 대신 정체불명의 연결 실패가 뜨고, 키를 잘못 맞춘
        // 배포자가 원인을 찾을 방법이 사라진다. 실제로 배포에서 그 일이 있었다.
        mvc.perform(post("/api/tenant/install-link").header("Origin", "http://localhost:5173"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:5173"));
    }
}
