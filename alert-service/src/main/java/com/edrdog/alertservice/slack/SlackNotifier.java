package com.edrdog.alertservice.slack;

import com.edrdog.alertservice.dto.Alert;
import com.edrdog.alertservice.webhook.TenantWebhookClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.Map;
import java.util.Optional;

/**
 * alert 를 tenant 별 Slack Incoming Webhook 으로 전송한다.
 * tenantId 로 {@link TenantWebhookClient} 를 통해 webhook 을 조회하고,
 * 미등록(empty) 이면 발송을 건너뛴다. 메시지 포맷(format)은 순수 로직으로 분리해 단위 테스트한다.
 */
@Component
public class SlackNotifier {

    private static final Logger log = LoggerFactory.getLogger(SlackNotifier.class);

    private final RestClient client;
    private final TenantWebhookClient webhooks;

    public SlackNotifier(RestClient.Builder builder, TenantWebhookClient webhooks) {
        this.client = builder.build();
        this.webhooks = webhooks;
    }

    /** alert 를 tenant webhook 으로 전송. 미등록 시 경고 로그 후 skip. */
    public void send(Alert alert) {
        Optional<String> webhookUrl = webhooks.resolve(alert.tenantId());
        if (webhookUrl.isEmpty()) {
            log.warn("tenant webhook 미등록 → 발송 skip (tenant={}, host={}, rule={})",
                    alert.tenantId(), alert.host(), alert.ruleId());
            return;
        }
        try {
            client.post()
                    .uri(webhookUrl.get())
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of("text", format(alert)))
                    .retrieve()
                    .toBodilessEntity();
        } catch (Exception e) {
            log.warn("Slack 발송 실패 (tenant={}, host={}, rule={}): {}",
                    alert.tenantId(), alert.host(), alert.ruleId(), e.getMessage());
        }
    }

    /** alert → Slack 메시지 한 줄. 심각도 아이콘 + 핵심 필드. */
    static String format(Alert alert) {
        return String.format("%s [%s] host=%s rule=%s mitre=%s action=%s",
                icon(alert.severity()), alert.severity(),
                alert.host(), alert.ruleId(), alert.mitre(), alert.action());
    }

    private static String icon(String severity) {
        return switch (severity == null ? "" : severity) {
            case Alert.SEV_CRITICAL -> "🔴";
            case Alert.SEV_HIGH -> "🟠";
            case Alert.SEV_MEDIUM -> "🟡";
            default -> "⚪";
        };
    }
}
