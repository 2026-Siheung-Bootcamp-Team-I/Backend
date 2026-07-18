package com.edrdog.detector.global;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.kafka.common.serialization.Deserializer;
import org.apache.kafka.common.serialization.Serde;
import org.apache.kafka.common.serialization.Serializer;

/** record/POJO ↔ JSON 바이트 변환용 범용 Serde. */
public class JsonSerde<T> implements Serde<T> {

    // 파생 getter 나 이벤트 여분 필드에 견디도록 unknown 프로퍼티 무시
    private static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    private final Class<T> type;

    // 역직렬화 대상 타입을 받아 보관 (제네릭이 런타임에 지워지므로 Class 로 명시)
    public JsonSerde(Class<T> type) {
        this.type = type;
    }

    // 객체 → JSON 바이트 (null 은 그대로 통과)
    @Override
    public Serializer<T> serializer() {
        return (topic, data) -> {
            if (data == null) return null;
            try {
                return MAPPER.writeValueAsBytes(data);
            } catch (Exception e) {
                throw new RuntimeException("serialize 실패: " + type.getSimpleName(), e);
            }
        };
    }

    // JSON 바이트 → 객체 (null 은 그대로 통과)
    @Override
    public Deserializer<T> deserializer() {
        return (topic, bytes) -> {
            if (bytes == null) return null;
            try {
                return MAPPER.readValue(bytes, type);
            } catch (Exception e) {
                throw new RuntimeException("deserialize 실패: " + type.getSimpleName(), e);
            }
        };
    }
}
