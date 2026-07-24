package com.edrdog.alert.slack;

import com.edrdog.alert.dto.Alert;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** alert → Slack 메시지 텍스트 포맷 검증 (순수 로직). */
class SlackNotifierTest {

    private Alert alert(String severity, String action) {
        return new Alert("host-1", "SUSPICIOUS_PROCESS_CHAIN", "T1059", severity, action, 1_000, List.of("evidence"), "", 0);
    }

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
}
