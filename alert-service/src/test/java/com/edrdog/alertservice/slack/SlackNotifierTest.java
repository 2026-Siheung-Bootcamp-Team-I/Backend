package com.edrdog.alertservice.slack;

import com.edrdog.alertservice.dto.Alert;
import com.edrdog.alertservice.webhook.TenantWebhookClient;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.test.web.client.ExpectedCount.never;
import static org.springframework.test.web.client.ExpectedCount.once;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.anything;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/** SlackNotifier: 메시지 포맷(순수) + tenant webhook 라우팅 검증. */
class SlackNotifierTest {

    private Alert alert(String severity, String action) {
        return new Alert("t1", "host-1", "SUSPICIOUS_PROCESS_CHAIN", "T1059", severity, action, 1_000, List.of("evidence"));
    }

    // --- 순수 포맷 ---

    @Test
    @DisplayName("메시지에 host, rule, mitre, severity, action 이 모두 담긴다")
    void format_containsAllFields() {
        String text = SlackNotifier.format(alert(Alert.SEV_HIGH, Alert.ACTION_KILL));

        assertThat(text).contains("host-1");
        assertThat(text).contains("SUSPICIOUS_PROCESS_CHAIN");
        assertThat(text).contains("T1059");
        assertThat(text).contains("HIGH");
        assertThat(text).contains("kill");
    }

    @Test
    @DisplayName("CRITICAL 은 🔴, HIGH 는 🟠 아이콘으로 구분된다")
    void format_severityIcon() {
        assertThat(SlackNotifier.format(alert(Alert.SEV_CRITICAL, Alert.ACTION_ISOLATE))).startsWith("🔴");
        assertThat(SlackNotifier.format(alert(Alert.SEV_HIGH, Alert.ACTION_KILL))).startsWith("🟠");
    }

    // --- 라우팅 ---

    @Test
    @DisplayName("tenant webhook 이 있으면 그 URL 로 POST 한다")
    void send_postsToResolvedWebhook() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        TenantWebhookClient webhooks = mock(TenantWebhookClient.class);
        when(webhooks.resolve("t1")).thenReturn(Optional.of("https://hooks/abc"));
        SlackNotifier notifier = new SlackNotifier(builder, webhooks);

        server.expect(once(), requestTo("https://hooks/abc"))
                .andExpect(method(POST))
                .andRespond(withSuccess());

        notifier.send(alert(Alert.SEV_HIGH, Alert.ACTION_KILL));
        server.verify();
    }

    @Test
    @DisplayName("tenant webhook 이 미등록이면 발송하지 않는다 (skip)")
    void send_skipsWhenUnregistered() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        TenantWebhookClient webhooks = mock(TenantWebhookClient.class);
        when(webhooks.resolve("t1")).thenReturn(Optional.empty());
        SlackNotifier notifier = new SlackNotifier(builder, webhooks);

        server.expect(never(), anything());

        notifier.send(alert(Alert.SEV_HIGH, Alert.ACTION_KILL));
        server.verify();
    }
}
