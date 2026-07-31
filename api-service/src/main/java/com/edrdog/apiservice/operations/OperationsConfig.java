package com.edrdog.apiservice.operations;

import org.apache.kafka.clients.admin.Admin;
import org.apache.kafka.clients.admin.AdminClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.core.KafkaAdmin;

/**
 * 파이프라인 상태 조회(operations/health) 전용 Kafka AdminClient.
 * KafkaAdmin(스프링이 spring.kafka.* 로 이미 자동구성)의 설정을 그대로 재사용해
 * bootstrap-servers 를 여기서 다시 하드코딩하지 않는다.
 * Admin 은 Closeable 이라 스프링이 컨텍스트 종료 시 자동으로 close() 한다.
 */
@Configuration
public class OperationsConfig {

    @Bean
    public Admin operationsKafkaAdminClient(KafkaAdmin kafkaAdmin) {
        return AdminClient.create(kafkaAdmin.getConfigurationProperties());
    }
}
