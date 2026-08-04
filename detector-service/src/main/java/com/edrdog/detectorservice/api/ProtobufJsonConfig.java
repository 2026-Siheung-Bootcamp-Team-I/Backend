package com.edrdog.detectorservice.api;

import com.edrdog.schema.ProtobufJacksonModule;
import com.fasterxml.jackson.databind.Module;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 데모 REST 가 이벤트를 JSON 으로 주고받게 한다.
 * Kafka 로는 Protobuf 로 나가지만 사람이 호출하는 자리까지 바이너리로 만들 이유는 없다.
 */
@Configuration
public class ProtobufJsonConfig {

    @Bean
    public Module protobufJacksonModule() {
        return new ProtobufJacksonModule();
    }
}
