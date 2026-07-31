package com.edrdog.apiservice.demo;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

/**
 * 데모 이벤트를 events 토픽으로 발행한다 (detector Kafka Streams 의 입력).
 * host 를 파티션 키로 보내 같은 엔드포인트 이벤트의 순서를 보존한다 — 시퀀스 룰이 순서에 의존한다.
 *
 * <p>에이전트 수집 입구(EventsRawProducer, events-raw)와 달리 정규화된 events 로 바로 보낸다.
 * 발표에서 보여줄 구간이 "Kafka → Streams → Kafka" 라 collector 정규화 단계는 지나가지 않는다.
 */
@Component
public class EventsProducer {

    private final KafkaTemplate<String, String> template;
    private final String eventsTopic;
    private final ObjectMapper mapper = new ObjectMapper();

    public EventsProducer(KafkaTemplate<String, String> template,
                          @Value("${edrdog.kafka.events-topic}") String eventsTopic) {
        this.template = template;
        this.eventsTopic = eventsTopic;
    }

    /** 인자 순서대로 같은 파티션에 쌓이므로 호출 순서가 곧 판정 순서다. */
    public void publish(CollectedEvent event) {
        try {
            template.send(eventsTopic, event.host(), mapper.writeValueAsString(event));
        } catch (Exception e) {
            throw new IllegalStateException("데모 이벤트 발행 실패: " + event, e);
        }
    }
}
