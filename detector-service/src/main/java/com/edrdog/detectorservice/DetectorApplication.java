package com.edrdog.detectorservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class DetectorApplication {

    // detector 모듈 진입점 — Spring Boot 부팅 (Kafka Streams는 KafkaStreamsConfig가 자동 기동)
    public static void main(String[] args) {
        SpringApplication.run(DetectorApplication.class, args);
    }
}
