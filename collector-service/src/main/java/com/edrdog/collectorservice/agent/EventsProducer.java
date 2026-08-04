package com.edrdog.collectorservice.agent;

import com.edrdog.schema.Event;
import com.edrdog.schema.EventHeaders;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

/**
 * 검증을 통과한 이벤트를 events 로 발행한다(detector/archiver 입력).
 *
 * <p>여기가 직렬화 지점이다. 수집 API 가 받는 원본은 JSON 이지만 검증과 정규화를 지난 뒤부터는
 * Protobuf 바이트로 나간다. 매 건 반복되던 필드명이 필드번호 태그로 바뀌어 전송량이 준다.
 *
 * <p>host 를 파티션 키로 보내 detector 상관분석의 host 별 순서를 보존한다.
 */
@Component
public class EventsProducer {

    private static final Logger log = LoggerFactory.getLogger(EventsProducer.class);

    private final KafkaTemplate<String, byte[]> template;
    private final String eventsTopic;
    private final PayloadSizeMeter payloadSize;   // 측정용 임시 의존. 수치를 확정하면 같이 걷어낸다

    public EventsProducer(KafkaTemplate<String, byte[]> template,
                          @Value("${edrdog.kafka.events-topic}") String eventsTopic,
                          PayloadSizeMeter payloadSize) {
        this.template = template;
        this.eventsTopic = eventsTopic;
        this.payloadSize = payloadSize;
    }

    /** 1건 발행. 실패하면 false 를 돌려 응답 accepted 에서 빠지게 한다. */
    public boolean publish(Event event) {
        try {
            // 본문이 바이너리라 kafbat UI 로 못 읽는다. 헤더가 그 자리를 메우므로 ProducerRecord 로 직접 만든다.
            byte[] payload = event.toByteArray();
            ProducerRecord<String, byte[]> record =
                    new ProducerRecord<>(eventsTopic, event.getHost(), payload);
            EventHeaders.stamp(record.headers(), event);
            template.send(record);
            payloadSize.record(event, payload);
            return true;
        } catch (Exception e) {
            log.error("events 발행 실패: {}", event, e);
            return false;
        }
    }
}
