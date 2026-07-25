package com.edrdog.apiservice.demo;

import com.edrdog.apiservice.alert.AlertService;
import com.edrdog.apiservice.alert.web.AlertResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultMatcher;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 발표용 데모 수집 API 배선 검증. 데모 시드를 켜고 전체 컨텍스트를 띄운다 — 발표 당일에 빈 배선이
 * 어긋나 있는 것보다 여기서 깨지는 게 낫다.
 *
 * <p>인증 헤더 없이 호출된다는 것 자체가 계약이다(스웨거에서 Execute 한 번). 대신 발행 대상 tenant 를
 * 호출자가 못 정하고 서버가 데모 계정에서 찾아 쓴다는 것을 함께 확인한다.
 *
 * <p>Kafka/ClickHouse 없이 확인하려고 발행(EventsProducer)·도착 관측(AlertArrivals)·조회(AlertService)를
 * 목으로 대체하고, 컨트롤러가 무엇을 어떤 순서로 발행하고 어떤 타임라인을 만드는지만 검증한다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.ANY)
@TestPropertySource(properties = {
        "spring.kafka.listener.auto-startup=false",
        "edrdog.demo.seed=true",
        // 대기 상한을 짧게: 테스트가 실제 12초를 흘려보낼 이유가 없다
        "edrdog.demo.detect-timeout-ms=300",
        "edrdog.demo.store-timeout-ms=300"
})
class DemoCollectIntegrationTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper om;

    @MockitoBean
    private EventsProducer producer;     // Kafka 대신 목: 발행 인자와 순서만 검증

    @MockitoBean
    private AlertArrivals arrivals;      // alerts 토픽 도착 관측 대체

    @MockitoBean
    private AlertService alerts;         // ClickHouse 조회 대체

    @Test
    void 인증_없이_호출해도_수집부터_저장까지_타임라인이_나온다() throws Exception {
        givenDetectionSucceeds();

        JsonNode res = collect(DemoScenario.DOWNLOAD_EXEC, status().isOk());

        assertEquals("download-exec", res.get("scenario").asText());
        assertEquals("DESKTOP-CHOI", res.get("host").asText());   // 시나리오 기본 host
        assertEquals(3, res.get("steps").size());
        for (JsonNode step : res.get("steps")) {
            assertEquals("OK", step.get("status").asText(), step.toString());
        }
        assertEquals("DOWNLOAD_AND_EXECUTE", res.get("alert").get("ruleId").asText());
        assertTrue(res.get("alertId").asText().length() > 0);
    }

    @Test
    void 발행_대상_tenant_는_데모_계정에서_찾은_값이다() throws Exception {
        // 호출자가 tenant 를 지정할 방법이 없다는 것이 이 API 의 안전장치다.
        givenDetectionSucceeds();

        JsonNode res = collect(DemoScenario.DOWNLOAD_EXEC, status().isOk());

        String demoTenant = String.valueOf(DemoAccountSeeder.TENANT_ID);
        assertEquals(demoTenant, res.get("tenantId").asText());
        ArgumentCaptor<CollectedEvent> captor = ArgumentCaptor.forClass(CollectedEvent.class);
        verify(producer, Mockito.atLeastOnce()).publish(captor.capture());
        assertTrue(captor.getAllValues().stream().allMatch(e -> demoTenant.equals(e.tenantId())));
    }

    @Test
    void 발행_순서가_배경_로그_다음_공격_이벤트다() throws Exception {
        givenDetectionSucceeds();

        collect(DemoScenario.DOWNLOAD_EXEC, status().isOk());

        ArgumentCaptor<CollectedEvent> captor = ArgumentCaptor.forClass(CollectedEvent.class);
        verify(producer, Mockito.times(5)).publish(captor.capture());
        List<CollectedEvent> published = captor.getAllValues();
        assertEquals(List.of("OneDrive.exe", "Teams.exe", "MsEdgeUpdate.exe", "chrome.exe", "update32.exe"),
                published.stream().map(CollectedEvent::process).toList());
        assertEquals(CollectedEvent.TYPE_NETWORK, published.get(3).type());
        assertTrue(published.stream().allMatch(e -> "DESKTOP-CHOI".equals(e.host())));
    }

    @Test
    void 판정이_돌아오지_않으면_탐지_단계가_TIMEOUT_으로_남는다() throws Exception {
        when(arrivals.arrivedAt(anyString())).thenReturn(Optional.empty());

        JsonNode res = collect(DemoScenario.SCRIPT_EXEC, status().isOk());

        assertEquals(2, res.get("steps").size());   // 수집 OK + 탐지 TIMEOUT (저장은 시도하지 않는다)
        assertEquals("OK", res.get("steps").get(0).get("status").asText());
        assertEquals("TIMEOUT", res.get("steps").get(1).get("status").asText());
        assertTrue(res.get("steps").get(1).get("detail").asText().contains("300ms"));
        assertTrue(res.get("alert").isNull());
    }

    @Test
    void 미지원_시나리오는_400_이고_아무것도_발행하지_않는다() throws Exception {
        collect("ransomware", status().isBadRequest());

        verify(producer, Mockito.never()).publish(any());
    }

    /** 판정이 alerts 토픽으로 돌아오고 조회까지 되는 정상 경로. */
    private void givenDetectionSucceeds() {
        when(arrivals.arrivedAt(anyString())).thenReturn(Optional.of(System.currentTimeMillis()));
        when(alerts.get(anyString(), anyString())).thenAnswer(inv -> new AlertResponse(
                inv.getArgument(1), "DESKTOP-CHOI", "DOWNLOAD_AND_EXECUTE", "다운로드 후 실행",
                "T1105+T1204", "CRITICAL", "kill", System.currentTimeMillis(), "open",
                List.of("network 185.220.101.5:443", "process update32.exe")));
    }

    /** 헤더 하나 없이 호출한다 — 발표에서 스웨거 Execute 를 누르는 것과 같다. */
    private JsonNode collect(String scenario, ResultMatcher expected) throws Exception {
        String body = mvc.perform(post("/api/demo/collect/" + scenario))
                .andExpect(expected)
                .andReturn().getResponse().getContentAsString();
        return body.isEmpty() ? om.createObjectNode() : om.readTree(body);
    }
}
