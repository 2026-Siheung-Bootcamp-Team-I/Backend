package com.edrdog.alertservice.slack;

import com.edrdog.alertservice.dto.Alert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.Map;

/**
 * alert 를 지정된 Slack Incoming Webhook 으로 전송한다.
 * 목적지(webhook) 결정은 {@link com.edrdog.alertservice.webhook.AlertRouter} 가 담당하고,
 * 여기서는 받은 URL 로 POST 만 한다. 메시지 포맷(format)은 순수 로직으로 분리해 단위 테스트한다.
 */
@Component
public class SlackNotifier {

    private static final Logger log = LoggerFactory.getLogger(SlackNotifier.class);

    private final RestClient client;

    public SlackNotifier(RestClient.Builder builder) {
        this.client = builder.build();
    }

    /** alert 를 주어진 webhook URL 로 전송. 실패는 경고 로그만 남기고 삼킨다. */
    public void send(Alert alert, String webhookUrl) {
        try {
            client.post()
                    .uri(webhookUrl)
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
