package com.edrdog.schema;

import org.apache.kafka.common.serialization.Serializer;

/** Event → Protobuf 바이트. Spring Kafka 가 설정에서 클래스 이름으로 가져가므로 최상위 클래스로 둔다. */
public class EventSerializer implements Serializer<Event> {

    @Override
    public byte[] serialize(String topic, Event data) {
        return data == null ? null : data.toByteArray();
    }
}
