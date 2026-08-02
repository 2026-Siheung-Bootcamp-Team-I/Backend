package com.edrdog.collectorservice.agent;

import com.edrdog.collectorservice.dto.Event;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

/**
 * 검증을 통과한 이벤트를 events 로 발행한다(detector/archiver 입력).
 * host 를 파티션 키로 보내 detector 상관분석의 host 별 순서를 보존한다.
 */
@Component
public class EventsProducer {

    private static final Logger log = LoggerFactory.getLogger(EventsProducer.class);

    private final KafkaTemplate<String, String> template;
    private final String eventsTopic;
    private final ObjectMapper mapper = new ObjectMapper();

    public EventsProducer(KafkaTemplate<String, String> template,
                          @Value("${edrdog.kafka.events-topic}") String eventsTopic) {
        this.template = template;
        this.eventsTopic = eventsTopic;
    }

    /** 1건 발행. 실패하면 false 를 돌려 응답 accepted 에서 빠지게 한다. */
    public boolean publish(Event event) {
        try {
            template.send(eventsTopic, event.host(), mapper.writeValueAsString(event));
            return true;
        } catch (Exception e) {
            log.error("events 발행 실패: {}", event, e);
            return false;
        }
    }
}
