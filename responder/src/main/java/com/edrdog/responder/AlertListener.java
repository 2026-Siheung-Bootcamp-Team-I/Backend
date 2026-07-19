package com.edrdog.responder;

import com.edrdog.responder.dto.Alert;
import com.edrdog.responder.response.ResponsePlanner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

/**
 * alerts 토픽을 소비해 권장 조치를 dry-run 으로 표시(로그)만 하는 리스너.
 * 판정/쿨다운은 ResponsePlanner(순수 로직)에 위임하고, 여기서는 소비와 로그 출력만 담당한다.
 */
@Component
public class AlertListener {

    private static final Logger log = LoggerFactory.getLogger(AlertListener.class);

    private final ResponsePlanner planner;

    public AlertListener(@Value("${edrdog.responder.cooldown-ms}") long cooldownMs) {
        this.planner = new ResponsePlanner(cooldownMs);
    }

    @KafkaListener(topics = "${edrdog.kafka.alerts-topic}", groupId = "${spring.kafka.consumer.group-id}")
    public void onAlert(Alert alert) {
        planner.plan(alert).ifPresent(log::info);
    }
}
