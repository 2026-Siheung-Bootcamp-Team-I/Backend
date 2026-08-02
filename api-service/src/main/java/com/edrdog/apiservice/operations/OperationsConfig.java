package com.edrdog.apiservice.operations;

import org.apache.kafka.clients.admin.Admin;
import org.apache.kafka.clients.admin.AdminClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.core.KafkaAdmin;

/**
 * 파이프라인 상태 조회(operations/health) 전용 Kafka AdminClient.
 * KafkaAdmin(spring.kafka.* 자동구성)의 설정을 그대로 재사용해 bootstrap-servers 를 다시 하드코딩하지 않는다.
 */
@Configuration
public class OperationsConfig {

    @Bean
    public Admin operationsKafkaAdminClient(KafkaAdmin kafkaAdmin) {
        return AdminClient.create(kafkaAdmin.getConfigurationProperties());
    }
}
