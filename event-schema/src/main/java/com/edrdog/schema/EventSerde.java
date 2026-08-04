package com.edrdog.schema;

import org.apache.kafka.common.serialization.Deserializer;
import org.apache.kafka.common.serialization.Serde;
import org.apache.kafka.common.serialization.Serializer;

/**
 * Kafka Streams 용 Event Serde. 실제 변환은 {@link EventSerializer}/{@link EventDeserializer} 가 한다.
 * Spring Kafka 쪽과 같은 코드를 쓰게 하려고 여기서 감싸기만 한다.
 */
public class EventSerde implements Serde<Event> {

    @Override
    public Serializer<Event> serializer() {
        return new EventSerializer();
    }

    @Override
    public Deserializer<Event> deserializer() {
        return new EventDeserializer();
    }
}
