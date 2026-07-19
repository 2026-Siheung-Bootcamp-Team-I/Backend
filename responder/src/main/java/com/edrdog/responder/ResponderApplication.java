package com.edrdog.responder;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** alerts 를 소비해 권장 조치를 dry-run 으로 표시하는 responder 서비스. */
@SpringBootApplication
public class ResponderApplication {

    public static void main(String[] args) {
        SpringApplication.run(ResponderApplication.class, args);
    }
}
