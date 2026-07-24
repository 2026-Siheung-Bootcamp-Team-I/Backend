package com.edrdog.archiver;

import com.edrdog.archiver.dto.Alert;
import java.util.HashMap;
import java.util.Map;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory;
import org.springframework.kafka.core.ConsumerFactory;
import org.springframework.kafka.core.DefaultKafkaConsumerFactory;
import org.springframework.kafka.support.serializer.JsonDeserializer;

/**
 * alerts 토픽 전용 컨슈머 팩토리.
 * 기본 팩토리는 spring.json.value.default.type 을 Event 로 고정해두었기 때문에,
 * 같은 팩토리로 Alert 를 받으면 Event 로 잘못 역직렬화된다. Alert 전용 팩토리를 별도로 두어
 * AlertListener 가 이 팩토리를 명시적으로 사용하게 한다. 기존 EventListener + 기본 팩토리는
 * 그대로 둔다.
 */
@Configuration
public class KafkaAlertConfig {

    @Bean
    public ConsumerFactory<String, Alert> alertConsumerFactory(
            @Value("${spring.kafka.bootstrap-servers}") String bootstrapServers,
            @Value("${spring.kafka.consumer.auto-offset-reset}") String autoOffsetReset) {
        Map<String, Object> props = new HashMap<>();
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, autoOffsetReset);
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, JsonDeserializer.class);
        props.put(JsonDeserializer.VALUE_DEFAULT_TYPE, Alert.class.getName());
        props.put(JsonDeserializer.TRUSTED_PACKAGES, "com.edrdog.archiver.dto");
        return new DefaultKafkaConsumerFactory<>(props);
    }

    @Bean
    public ConcurrentKafkaListenerContainerFactory<String, Alert> alertKafkaListenerContainerFactory(
            ConsumerFactory<String, Alert> alertConsumerFactory) {
        ConcurrentKafkaListenerContainerFactory<String, Alert> factory =
                new ConcurrentKafkaListenerContainerFactory<>();
        factory.setConsumerFactory(alertConsumerFactory);
        return factory;
    }
}
