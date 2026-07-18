package com.edrdog.detector.global;

import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.annotation.EnableKafkaStreams;

/**
 * Kafka Streams 활성화. bootstrap-servers/application-id/serde 는 application.yml 에서 주입.
 * NOTE: 토폴로지(상관분석)를 이식하기 전엔 빈 토폴로지라 앱 실행 시 에러날 수 있음 — 스키마 설계 후 이식.
 */
@Configuration
@EnableKafkaStreams
public class KafkaStreamsConfig {
}
