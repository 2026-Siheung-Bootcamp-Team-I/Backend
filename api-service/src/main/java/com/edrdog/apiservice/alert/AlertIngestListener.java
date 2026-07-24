package com.edrdog.apiservice.alert;

import com.edrdog.apiservice.alert.dto.Alert;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

/**
 * alerts 토픽을 소비해 판정기록을 ClickHouse 에 적재하는 리스너(얇게).
 * 실제 격리·멱등 처리는 AlertService.ingest 가 담당한다(status 오버레이는 MySQL).
 */
@Component
public class AlertIngestListener {

    private final AlertService service;

    public AlertIngestListener(AlertService service) {
        this.service = service;
    }

    @KafkaListener(topics = "${edrdog.kafka.alerts-topic}", groupId = "${spring.kafka.consumer.group-id}")
    public void onAlert(Alert alert) {
        service.ingest(alert);
    }
}
