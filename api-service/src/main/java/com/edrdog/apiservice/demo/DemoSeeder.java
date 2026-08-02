package com.edrdog.apiservice.demo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/**
 * 발표용 시드의 유일한 진입점.
 * 조건부 빈을 풀면 운영에서도 데모 시드가 돌아간다({@code edrdog.demo.seed} 가 그걸 막는 유일한 장치다).
 * 계정과 데이터를 따로 떼면 tenant 확보 실패를 데이터 시드가 모른 채 남의 조직에 데모 alert 를 밀어넣는다.
 */
@Component
@ConditionalOnProperty(name = "edrdog.demo.seed", havingValue = "true")
public class DemoSeeder implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DemoSeeder.class);

    private final DemoAccountSeeder account;
    private final DemoDataSeeder data;

    public DemoSeeder(DemoAccountSeeder account, DemoDataSeeder data) {
        this.account = account;
        this.data = data;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (!account.seed()) {
            log.warn("데모 tenant 를 확보하지 못해 데이터 시드도 건너뜁니다. 남의 조직에 데모 데이터를 섞지 않습니다.");
            return;
        }
        data.seed();
    }
}
