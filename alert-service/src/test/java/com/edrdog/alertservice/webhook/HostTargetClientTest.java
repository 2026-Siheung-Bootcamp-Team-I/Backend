package com.edrdog.alertservice.webhook;

import com.edrdog.alertservice.webhook.HostTargetClient.Target;
import com.edrdog.alertservice.webhook.HostTargetClient.TargetResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;
import static org.springframework.http.HttpStatus.NOT_FOUND;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.client.ExpectedCount.once;
import static org.springframework.test.web.client.ExpectedCount.times;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/** host 소유 목적지 조회 클라이언트: 응답 매핑(순수) + HTTP(404/성공/캐시) 검증. */
class HostTargetClientTest {

    private static final String BASE = "http://api";
    private static final String KEY = "test-key";

    // --- 순수 응답 매핑 ---

    @Test
    @DisplayName("null 응답은 empty")
    void toTarget_null() {
        assertThat(HostTargetClient.toTarget(null)).isEmpty();
    }

    @Test
    @DisplayName("webhookUrl 이 null 이면 empty")
    void toTarget_nullUrl() {
        assertThat(HostTargetClient.toTarget(new TargetResponse(10L, null))).isEmpty();
    }

    @Test
    @DisplayName("userId+webhookUrl 이 있으면 Target 반환")
    void toTarget_present() {
        assertThat(HostTargetClient.toTarget(new TargetResponse(10L, "https://hooks/u")))
                .contains(new Target(10L, "https://hooks/u"));
    }

    // --- HTTP ---

    @Test
    @DisplayName("404(소유자 없음) 는 empty, tenantId+host 를 쿼리로 GET")
    void resolve_notFound_empty() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        HostTargetClient client = new HostTargetClient(builder, BASE, KEY, 60_000);

        server.expect(once(), requestTo(BASE + "/api/internal/alert-target?tenantId=7&host=host-1"))
                .andExpect(method(GET))
                .andExpect(header("X-Internal-Key", KEY))
                .andRespond(withStatus(NOT_FOUND));

        assertThat(client.resolve("7", "host-1")).isEmpty();
        server.verify();
    }

    @Test
    @DisplayName("200 이면 Target 반환")
    void resolve_ok_returnsTarget() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        HostTargetClient client = new HostTargetClient(builder, BASE, KEY, 60_000);

        server.expect(once(), requestTo(BASE + "/api/internal/alert-target?tenantId=7&host=host-1"))
                .andRespond(withSuccess("{\"userId\":10,\"webhookUrl\":\"https://hooks/u\"}", APPLICATION_JSON));

        assertThat(client.resolve("7", "host-1")).contains(new Target(10L, "https://hooks/u"));
        server.verify();
    }

    @Test
    @DisplayName("404 는 캐시 → 두 번 조회해도 HTTP 1회")
    void resolve_notFound_cached() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        HostTargetClient client = new HostTargetClient(builder, BASE, KEY, 60_000);

        server.expect(once(), requestTo(BASE + "/api/internal/alert-target?tenantId=7&host=host-1"))
                .andRespond(withStatus(NOT_FOUND));

        assertThat(client.resolve("7", "host-1")).isEmpty();
        assertThat(client.resolve("7", "host-1")).isEmpty();
        server.verify();
    }

    @Test
    @DisplayName("일시 오류(5xx)는 캐시 안 함 → 재시도(HTTP 2회)")
    void resolve_transientError_notCached() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        HostTargetClient client = new HostTargetClient(builder, BASE, KEY, 60_000);

        server.expect(times(2), requestTo(BASE + "/api/internal/alert-target?tenantId=7&host=host-1"))
                .andRespond(withStatus(INTERNAL_SERVER_ERROR));

        assertThat(client.resolve("7", "host-1")).isEmpty();
        assertThat(client.resolve("7", "host-1")).isEmpty();
        server.verify();
    }
}
