package com.edrdog.alertservice.webhook;

import com.edrdog.alertservice.webhook.TenantWebhookClient.WebhookResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.ExpectedCount.once;
import static org.springframework.test.web.client.ExpectedCount.times;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;
import static org.springframework.http.HttpStatus.NOT_FOUND;
import static org.springframework.http.MediaType.APPLICATION_JSON;

/** tenant webhook 조회 클라이언트: 응답 매핑(순수) + HTTP(404/성공/캐시) 검증. */
class TenantWebhookClientTest {

    private static final String BASE = "http://api";
    private static final String KEY = "test-key";

    // --- 순수 응답 매핑 ---

    @Test
    @DisplayName("null 응답은 미등록(empty)")
    void toWebhook_null() {
        assertThat(TenantWebhookClient.toWebhook(null)).isEmpty();
    }

    @Test
    @DisplayName("webhookUrl 이 null 이면 미등록(empty)")
    void toWebhook_nullUrl() {
        assertThat(TenantWebhookClient.toWebhook(new WebhookResponse(1L, null))).isEmpty();
    }

    @Test
    @DisplayName("webhookUrl 이 있으면 그 값을 반환")
    void toWebhook_present() {
        assertThat(TenantWebhookClient.toWebhook(new WebhookResponse(1L, "https://hooks/x")))
                .contains("https://hooks/x");
    }

    // --- HTTP ---

    @Test
    @DisplayName("404 tenant 는 empty")
    void resolve_notFound_empty() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        TenantWebhookClient client = new TenantWebhookClient(builder, BASE, KEY, 60_000);

        server.expect(once(), requestTo(BASE + "/api/internal/tenants/7/webhook"))
                .andRespond(withStatus(NOT_FOUND));

        assertThat(client.resolve("7")).isEmpty();
        server.verify();
    }

    @Test
    @DisplayName("200 + webhookUrl 이면 그 URL, X-API-Key 헤더를 실어 GET")
    void resolve_ok_returnsUrl() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        TenantWebhookClient client = new TenantWebhookClient(builder, BASE, KEY, 60_000);

        server.expect(once(), requestTo(BASE + "/api/internal/tenants/7/webhook"))
                .andExpect(method(GET))
                .andExpect(header("X-Internal-Key", KEY))
                .andRespond(withSuccess("{\"tenantId\":7,\"webhookUrl\":\"https://hooks/abc\"}", APPLICATION_JSON));

        assertThat(client.resolve("7")).contains("https://hooks/abc");
        server.verify();
    }

    @Test
    @DisplayName("404(미등록) 는 캐시한다 → 두 번 조회해도 HTTP 1회")
    void resolve_notFound_cached_singleCall() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        TenantWebhookClient client = new TenantWebhookClient(builder, BASE, KEY, 60_000);

        server.expect(once(), requestTo(BASE + "/api/internal/tenants/7/webhook"))
                .andRespond(withStatus(NOT_FOUND));

        assertThat(client.resolve("7")).isEmpty();
        assertThat(client.resolve("7")).isEmpty();
        server.verify();  // 호출이 1회뿐이어야 통과
    }

    @Test
    @DisplayName("일시 조회 오류(5xx)는 캐시하지 않는다 → 다음 조회 때 재시도(HTTP 2회)")
    void resolve_transientError_notCached_retries() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        TenantWebhookClient client = new TenantWebhookClient(builder, BASE, KEY, 60_000);

        server.expect(times(2), requestTo(BASE + "/api/internal/tenants/7/webhook"))
                .andRespond(withStatus(INTERNAL_SERVER_ERROR));

        assertThat(client.resolve("7")).isEmpty();
        assertThat(client.resolve("7")).isEmpty();
        server.verify();  // 2회 호출돼야 통과 (캐시 안 함)
    }

    @Test
    @DisplayName("TTL 안에서는 캐시로 재조회 없이 같은 값을 반환 (HTTP 1회)")
    void resolve_cached_singleHttpCall() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        TenantWebhookClient client = new TenantWebhookClient(builder, BASE, KEY, 60_000);

        server.expect(once(), requestTo(BASE + "/api/internal/tenants/7/webhook"))
                .andRespond(withSuccess("{\"tenantId\":7,\"webhookUrl\":\"https://hooks/abc\"}", APPLICATION_JSON));

        assertThat(client.resolve("7")).contains("https://hooks/abc");
        assertThat(client.resolve("7")).contains("https://hooks/abc");
        server.verify();
    }
}
