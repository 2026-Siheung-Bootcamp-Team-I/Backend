package com.edrdog.apiservice.demo;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 데모 계정이 없는 환경에서는 데모 API 가 아무 일도 하지 않는다는 계약.
 *
 * <p>이 API 는 인증을 받지 않으므로, "쓸 수 있는 환경" 을 가르는 것은 데모 계정의 존재 여부다.
 * 계정은 시드({@code edrdog.demo.seed=true})로만 생기니, 시드를 켠 적 없는 환경에서는 tenant 를
 * 찾지 못해 403 이 되고 이벤트가 한 건도 나가지 않는다. 시드 플래그로 빈을 끄는 것과 같은 효과이면서,
 * 발표 환경에서는 파드 재시작 없이 바로 쓸 수 있다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.ANY)
@TestPropertySource(properties = {
        "spring.kafka.listener.auto-startup=false",
        "edrdog.demo.seed=false"
})
class DemoApiWithoutSeedTest {

    @Autowired
    private MockMvc mvc;

    @MockitoBean
    private EventsProducer producer;

    @Test
    void 데모_계정이_없으면_403_이고_이벤트를_발행하지_않는다() throws Exception {
        // 404 면 빈이 안 올라온 것이라 시드만 켜서 재시작 없이 쓴다는 성질이 깨진다.
        mvc.perform(post("/api/demo/collect/script-exec"))
                .andExpect(status().isForbidden());

        verify(producer, never()).publish(any());
    }
}
