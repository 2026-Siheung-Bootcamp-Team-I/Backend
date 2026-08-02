package com.edrdog.collectorservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** 에이전트 HTTP 를 직접 받아 인증·검증한 뒤 events 로 발행하는 수집 입구. */
@SpringBootApplication
public class CollectorApplication {

    public static void main(String[] args) {
        SpringApplication.run(CollectorApplication.class, args);
    }
}
