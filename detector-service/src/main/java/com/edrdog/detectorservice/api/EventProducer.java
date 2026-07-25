package com.edrdog.detectorservice.api;

import com.edrdog.detectorservice.dto.Event;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

/**
 * events 토픽으로 이벤트를 발행한다 (데모용 주입 경로).
 * 토폴로지가 JSON 페이로드로 소비하므로 value 를 JSON 문자열로 직렬화하고 key 는 host 로 보낸다.
 */
@Service
public class EventProducer {

    private final KafkaTemplate<String, String> template;
    private final String eventsTopic;
    private final ObjectMapper mapper = new ObjectMapper();

    public EventProducer(KafkaTemplate<String, String> template,
                         @Value("${edrdog.kafka.events-topic}") String eventsTopic) {
        this.template = template;
        this.eventsTopic = eventsTopic;
    }

    /** 이벤트 1건 발행. host 를 파티션 키로 사용해 같은 호스트 이벤트 순서를 보존. */
    public void publish(Event event) {
        try {
            template.send(eventsTopic, event.host(), mapper.writeValueAsString(event));
        } catch (Exception e) {
            throw new RuntimeException("이벤트 발행 실패", e);
        }
    }
}
