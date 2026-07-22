package com.edrdog.alertservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AlertApplication {

    // alert 모듈 진입점 — alerts 를 소비해 Slack 으로 알림 전송
    public static void main(String[] args) {
        SpringApplication.run(AlertApplication.class, args);
    }
}
