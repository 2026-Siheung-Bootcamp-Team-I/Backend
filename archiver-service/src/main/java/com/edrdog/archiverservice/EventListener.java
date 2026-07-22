package com.edrdog.archiverservice;

import com.edrdog.archiverservice.clickhouse.ClickHouseWriter;
import com.edrdog.archiverservice.dto.Event;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

/**
 * events 토픽을 archiver 컨슈머 그룹으로 소비해 ClickHouse 에 적재하는 리스너.
 * detector 와 별도 그룹이라 같은 이벤트를 독립적으로 모두 받는다. 적재는 ClickHouseWriter 에 위임.
 */
@Component
public class EventListener {

    private final ClickHouseWriter writer;

    public EventListener(ClickHouseWriter writer) {
        this.writer = writer;
    }

    @KafkaListener(topics = "${edrdog.kafka.events-topic}", groupId = "${spring.kafka.consumer.group-id}")
    public void onEvent(Event event) {
        writer.insert(event);
    }
}
