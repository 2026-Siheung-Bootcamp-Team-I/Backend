package com.edrdog.apiservice.osquery;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

/**
 * tenant 태깅된 osquery 원시 result-log 를 events-raw 로 발행한다(수집 입구).
 * collector 가 이 토픽을 소비해 Event 로 정규화 후 events 로 재발행한다.
 * host 를 파티션 키로 보내 같은 엔드포인트 이벤트 순서를 보존한다.
 */
@Service
public class EventsRawProducer {

    private final KafkaTemplate<String, String> template;
    private final String eventsRawTopic;

    public EventsRawProducer(KafkaTemplate<String, String> template,
                             @Value("${edrdog.kafka.events-raw-topic}") String eventsRawTopic) {
        this.template = template;
        this.eventsRawTopic = eventsRawTopic;
    }

    /** 원시 result-log JSON 1건 발행. key 는 host(엔드포인트 식별자). */
    public void publish(String host, String rawJson) {
        template.send(eventsRawTopic, host, rawJson);
    }
}
