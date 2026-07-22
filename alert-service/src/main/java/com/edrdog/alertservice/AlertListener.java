package com.edrdog.alertservice;

import com.edrdog.alertservice.dto.Alert;
import com.edrdog.alertservice.slack.SlackNotifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

/**
 * alerts 토픽을 소비해 Slack 으로 알림을 보내는 리스너.
 * 같은 host+ruleId 는 쿨다운 창 안에서 중복 발송을 억제한다 (Slack 스팸 방지).
 */
@Component
public class AlertListener {

    private final SlackNotifier slack;
    private final Cooldown cooldown;

    public AlertListener(@Value("${edrdog.alert.cooldown-ms}") long cooldownMs, SlackNotifier slack) {
        this.slack = slack;
        this.cooldown = new Cooldown(cooldownMs);
    }

    @KafkaListener(topics = "${edrdog.kafka.alerts-topic}", groupId = "${spring.kafka.consumer.group-id}")
    public void onAlert(Alert alert) {
        if (alert == null || alert.host() == null || alert.ruleId() == null) {
            return;
        }
        String key = alert.host() + "|" + alert.ruleId();
        if (cooldown.allow(key, alert.ts())) {
            slack.send(alert);
        }
    }
}
