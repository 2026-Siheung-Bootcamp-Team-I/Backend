package com.edrdog.collectorservice;

import com.edrdog.collectorservice.dto.Event;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * events-raw(에이전트가 보낸 이벤트 JSON 문자열)를 소비해 검증 후 events 로 재발행한다.
 * 검증 규칙은 순수 로직 {@link RawEventMapper} 에 위임하고, 여기서는 Kafka 입출력만 담당한다.
 * host 를 파티션 키로 보내 detector 상관분석의 host 별 순서를 보존한다.
 */
@Component
public class RawEventListener {

    private static final Logger log = LoggerFactory.getLogger(RawEventListener.class);

    private final KafkaTemplate<String, String> template;
    private final String eventsTopic;
    private final ObjectMapper mapper = new ObjectMapper();

    public RawEventListener(KafkaTemplate<String, String> template,
                            @Value("${edrdog.kafka.events-topic}") String eventsTopic) {
        this.template = template;
        this.eventsTopic = eventsTopic;
    }

    @KafkaListener(topics = "${edrdog.kafka.events-raw-topic}", groupId = "${spring.kafka.consumer.group-id}")
    public void onRaw(String raw) {
        Optional<Event> event = RawEventMapper.map(raw, mapper);
        if (event.isEmpty()) {
            return;   // 검증 실패(깨진 JSON/필수값 누락/알 수 없는 타입 등)는 조용히 버린다
        }
        Event e = event.get();
        try {
            template.send(eventsTopic, e.host(), mapper.writeValueAsString(e));
        } catch (Exception ex) {
            log.error("events 재발행 실패: {}", e, ex);
        }
    }
}
