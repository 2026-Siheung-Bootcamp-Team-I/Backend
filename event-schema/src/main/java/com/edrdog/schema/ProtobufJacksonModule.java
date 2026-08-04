package com.edrdog.schema;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.google.protobuf.Message;
import com.google.protobuf.util.JsonFormat;

import java.io.IOException;

/**
 * Protobuf 메시지를 Jackson 이 다루게 하는 모듈.
 *
 * <p>Kafka 로 나가는 이벤트는 바이너리지만, 데모 REST 는 사람이 읽고 쓰는 자리라 JSON 을 유지한다.
 * Jackson 기본 동작으로 생성 클래스를 직렬화하면 내부 필드까지 그대로 쏟아지므로
 * proto 의 정식 JSON 매핑({@link JsonFormat})을 태운다. 필드명은 lowerCamelCase 라 예전 JSON 과 같다.
 */
public class ProtobufJacksonModule extends SimpleModule {

    public ProtobufJacksonModule() {
        super("protobuf");
        addSerializer(Message.class, new MessageSerializer());
        addDeserializer(Event.class, new EventJsonDeserializer());
    }

    private static class MessageSerializer extends JsonSerializer<Message> {
        @Override
        public void serialize(Message value, JsonGenerator gen, SerializerProvider serializers) throws IOException {
            // 이미 JSON 문자열이라 다시 감싸지 않고 그대로 흘린다.
            gen.writeRawValue(JsonFormat.printer().omittingInsignificantWhitespace().print(value));
        }
    }

    private static class EventJsonDeserializer extends JsonDeserializer<Event> {
        @Override
        public Event deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
            JsonNode node = p.getCodec().readTree(p);
            Event.Builder builder = Event.newBuilder();
            // 모르는 필드는 무시한다. 스키마보다 앞서 나간 호출 하나가 요청 전체를 400 으로 만들지 않게.
            JsonFormat.parser().ignoringUnknownFields().merge(node.toString(), builder);
            return builder.build();
        }
    }
}
