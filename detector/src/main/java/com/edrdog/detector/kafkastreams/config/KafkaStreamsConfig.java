package com.edrdog.detector.kafkastreams.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.annotation.EnableKafkaStreams;

/**
 * Kafka Streams 활성화. bootstrap-servers/application-id/serde 는 application.yml 에서 주입.
 * 토폴로지는 DetectionTopology 가 StreamsBuilder 주입으로 등록한다.
 */
@Configuration
@EnableKafkaStreams
public class KafkaStreamsConfig {
}
