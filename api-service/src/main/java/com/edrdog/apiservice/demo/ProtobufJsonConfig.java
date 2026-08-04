package com.edrdog.apiservice.demo;

import com.edrdog.schema.ProtobufJacksonModule;
import com.fasterxml.jackson.databind.Module;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 데모 수집 API 응답에 발행한 이벤트를 그대로 실어 준다(collectedLogs).
 * 스키마 클래스는 Protobuf 생성 코드라 Jackson 기본 동작으로는 내부 필드까지 쏟아진다.
 */
@Configuration
public class ProtobufJsonConfig {

    @Bean
    public Module protobufJacksonModule() {
        return new ProtobufJacksonModule();
    }
}
