package com.edrdog.detectorservice.api;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** 시나리오 발행의 tenantId 검증 배선: PK 아니면 400, 유효 PK 면 발행. */
@WebMvcTest(IngestController.class)
class IngestControllerTest {

    @Autowired
    private MockMvc mvc;

    @MockitoBean
    private EventProducer producer;

    @MockitoBean
    private RecentAlerts recentAlerts;

    @Test
    @DisplayName("tenantId 가 PK(정수) 아니면 400, 발행 안 함")
    void invalidTenantId_400() throws Exception {
        mvc.perform(post("/api/events/scenario/process-chain").param("tenantId", "tenant-a"))
                .andExpect(status().isBadRequest());
        verifyNoInteractions(producer);
    }

    @Test
    @DisplayName("tenantId 누락은 400")
    void missingTenantId_400() throws Exception {
        mvc.perform(post("/api/events/scenario/process-chain"))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("유효한 tenant PK 면 202 로 발행")
    void validPk_publishes() throws Exception {
        mvc.perform(post("/api/events/scenario/process-chain").param("tenantId", "1"))
                .andExpect(status().isAccepted());
        verify(producer, atLeastOnce()).publish(any());
    }
}
