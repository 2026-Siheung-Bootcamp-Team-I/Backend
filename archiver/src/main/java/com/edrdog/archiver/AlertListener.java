package com.edrdog.archiver;

import com.edrdog.archiver.clickhouse.ClickHouseWriter;
import com.edrdog.archiver.dto.Alert;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

/**
 * alerts 토픽을 archiver-alerts 그룹으로 소비해 ClickHouse detections 테이블에 적재하는 리스너.
 * 기본 컨슈머 팩토리는 spring.json.value.default.type 이 Event 로 고정되어 있어 그대로 쓰면 Alert 가
 * Event 로 잘못 역직렬화되므로, KafkaAlertConfig 가 제공하는 Alert 전용 팩토리를 사용한다.
 */
@Component
public class AlertListener {

    private final ClickHouseWriter writer;

    public AlertListener(ClickHouseWriter writer) {
        this.writer = writer;
    }

    @KafkaListener(
            topics = "${edrdog.kafka.alerts-topic}",
            groupId = "archiver-alerts",
            containerFactory = "alertKafkaListenerContainerFactory")
    public void onAlert(Alert alert) {
        writer.insert(alert);
    }
}
