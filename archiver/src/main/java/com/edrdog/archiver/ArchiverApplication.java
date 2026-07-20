package com.edrdog.archiver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** events 를 소비해 ClickHouse 에 적재하는 archiver 서비스 (detector 와 독립). */
@SpringBootApplication
public class ArchiverApplication {

    public static void main(String[] args) {
        SpringApplication.run(ArchiverApplication.class, args);
    }
}
