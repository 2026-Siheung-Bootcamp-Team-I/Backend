package com.edrdog.apiservice.demo;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 시드 플래그를 켜고 전체 컨텍스트를 띄워, 부팅 직후 데모 계정으로 실제 로그인이 되는지 검증한다.
 * tenant 는 네이티브 INSERT 로 넣기 때문에 컬럼명이 어긋나면 여기서 바로 드러난다(발표 당일 대신).
 */
@SpringBootTest
@AutoConfigureMockMvc
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.ANY)
@TestPropertySource(properties = {
        "spring.kafka.listener.auto-startup=false",
        "edrdog.demo.seed=true"
})
class DemoAccountSeederTest {

    private static final String LOGIN_BODY = "{\"email\":\"test\",\"password\":\"1234\"}";

    @Autowired
    private MockMvc mvc;

    @Autowired
    private DemoAccountSeeder seeder;

    @Test
    void 부팅_직후_test_1234_로_로그인되고_tenantId_는_고정값이다() throws Exception {
        mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(LOGIN_BODY))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isNotEmpty())
                .andExpect(jsonPath("$.email").value("test"))
                .andExpect(jsonPath("$.tenantId").value((int) DemoAccountSeeder.TENANT_ID));
    }

    @Test
    void 시더를_다시_돌려도_중복_없이_로그인이_유지된다() throws Exception {
        seeder.seed();

        mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(LOGIN_BODY))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tenantId").value((int) DemoAccountSeeder.TENANT_ID));
    }

    @Test
    void 잘못된_비밀번호는_그대로_거부된다() throws Exception {
        mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"test\",\"password\":\"wrong\"}"))
                .andExpect(status().isUnauthorized());
    }
}
