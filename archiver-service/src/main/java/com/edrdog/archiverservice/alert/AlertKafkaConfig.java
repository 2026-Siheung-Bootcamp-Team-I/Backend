package com.edrdog.archiverservice.alert;

import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory;
import org.springframework.kafka.core.ConsumerFactory;
import org.springframework.kafka.core.DefaultKafkaConsumerFactory;

import java.util.HashMap;
import java.util.Map;

/**
 * alerts 전용 컨슈머 설정. 전역 리스너 설정(application.yml spring.kafka.*)은 events 배치 적재에 묶여 있어
 * 공유하면 events 적재가 깨진다. 그래서 전용 ConsumerFactory/ContainerFactory 빈을 따로 둔다.
 */
@Configuration
public class AlertKafkaConfig {

    @Bean
    public ConsumerFactory<String, String> alertConsumerFactory(
            @Value("${spring.kafka.bootstrap-servers}") String bootstrapServers) {
        Map<String, Object> props = new HashMap<>();
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        props.put(ConsumerConfig.GROUP_ID_CONFIG, "archiver-alerts");
        props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");   // 판정기록은 유실 없이 처음부터 적재
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        // 값은 문자열로 받고 AlertIngestListener 에서 ObjectMapper 로 직접 파싱한다.
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        return new DefaultKafkaConsumerFactory<>(props);
    }

    @Bean
    public ConcurrentKafkaListenerContainerFactory<String, String> alertListenerContainerFactory(
            ConsumerFactory<String, String> alertConsumerFactory) {
        ConcurrentKafkaListenerContainerFactory<String, String> factory = new ConcurrentKafkaListenerContainerFactory<>();
        factory.setConsumerFactory(alertConsumerFactory);
        // 전용 팩토리라 spring.kafka.listener.concurrency 가 안 먹는다. alerts 파티션 수(3)에 맞춰 여기서 직접 준다.
        factory.setConcurrency(3);
        // 발행 측 traceId 를 이어받아 한 트레이스로 연결한다.
        factory.getContainerProperties().setObservationEnabled(true);
        return factory;
    }
}
