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
 * alerts 전용 컨슈머 설정. archiver 의 전역 리스너 설정(application.yml spring.kafka.*)은 events 적재를 위해
 * batch 리스너 + Event 타입 힌트 + group-id(archiver) 로 고정돼 있다. alerts 는 레코드 단위 리스너에
 * 별도 컨슈머 그룹(archiver-alerts)이 필요해 전역 설정을 공유할 수 없다(공유하면 events 적재가 깨진다).
 * 그래서 alerts 리스너 전용 ConsumerFactory/ContainerFactory 빈을 따로 둔다.
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
        // JsonDeserializer 의 타입 힌트 설정과 싸우는 대신 문자열로 받아 AlertIngestListener 에서 ObjectMapper 로 직접 파싱한다.
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        return new DefaultKafkaConsumerFactory<>(props);
    }

    @Bean
    public ConcurrentKafkaListenerContainerFactory<String, String> alertListenerContainerFactory(
            ConsumerFactory<String, String> alertConsumerFactory) {
        ConcurrentKafkaListenerContainerFactory<String, String> factory = new ConcurrentKafkaListenerContainerFactory<>();
        factory.setConsumerFactory(alertConsumerFactory);
        // 전역 listener.observation-enabled: true 와 같은 효과 — 발행 측 traceId 를 이어받아 한 트레이스로 연결.
        factory.getContainerProperties().setObservationEnabled(true);
        return factory;
    }
}
