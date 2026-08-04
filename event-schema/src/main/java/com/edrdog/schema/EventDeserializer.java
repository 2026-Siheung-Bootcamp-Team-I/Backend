package com.edrdog.schema;

import com.google.protobuf.InvalidProtocolBufferException;
import org.apache.kafka.common.serialization.Deserializer;

/**
 * Protobuf 바이트 → Event. Spring Kafka 가 설정에서 클래스 이름으로 가져가므로 최상위 클래스로 둔다.
 * 깨진 레코드를 조용히 빈 이벤트로 넘기면 어긋난 스키마가 판정과 적재까지 흘러들어 예외로 세운다.
 */
public class EventDeserializer implements Deserializer<Event> {

    @Override
    public Event deserialize(String topic, byte[] data) {
        if (data == null) {
            return null;
        }
        try {
            return Event.parseFrom(data);
        } catch (InvalidProtocolBufferException e) {
            throw new IllegalArgumentException("Event 역직렬화 실패 (topic=" + topic + ")", e);
        }
    }
}
