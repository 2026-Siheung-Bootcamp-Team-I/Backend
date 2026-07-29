package com.edrdog.collectorservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** 에이전트가 보낸 원시 이벤트(events-raw)를 검증해 events 로 재발행하는 collector 서비스. */
@SpringBootApplication
public class CollectorApplication {

    public static void main(String[] args) {
        SpringApplication.run(CollectorApplication.class, args);
    }
}
