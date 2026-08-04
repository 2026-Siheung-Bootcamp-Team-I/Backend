package com.edrdog.detectorservice.api;

import com.edrdog.schema.Event;
import com.edrdog.schema.EventHeaders;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

/**
 * events 토픽으로 이벤트를 발행한다 (데모용 주입 경로).
 * 토폴로지가 Protobuf 로 소비하므로 collector 와 같은 형식으로 보낸다. 여기만 JSON 으로 두면 판정이 통째로 깨진다.
 */
@Service
public class EventProducer {

    private final KafkaTemplate<String, byte[]> template;
    private final String eventsTopic;

    public EventProducer(KafkaTemplate<String, byte[]> template,
                         @Value("${edrdog.kafka.events-topic}") String eventsTopic) {
        this.template = template;
        this.eventsTopic = eventsTopic;
    }

    /** 이벤트 1건 발행. host 를 파티션 키로 사용해 같은 호스트 이벤트 순서를 보존. */
    public void publish(Event event) {
        try {
            ProducerRecord<String, byte[]> record =
                    new ProducerRecord<>(eventsTopic, event.getHost(), event.toByteArray());
            EventHeaders.stamp(record.headers(), event);
            template.send(record);
        } catch (Exception e) {
            throw new RuntimeException("이벤트 발행 실패", e);
        }
    }
}
