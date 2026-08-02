package com.edrdog.detectorservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

// detector 모듈 진입점. Kafka Streams 는 KafkaStreamsConfig 가 자동 기동
@SpringBootApplication
public class DetectorApplication {

    public static void main(String[] args) {
        SpringApplication.run(DetectorApplication.class, args);
    }
}
