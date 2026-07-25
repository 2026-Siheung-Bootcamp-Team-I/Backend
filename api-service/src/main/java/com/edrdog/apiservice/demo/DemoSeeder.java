package com.edrdog.apiservice.demo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/**
 * 발표용 시드의 유일한 진입점. {@code edrdog.demo.seed=true} 일 때만 빈으로 올라온다.
 *
 * <p>계정과 데이터를 굳이 한 진입점으로 묶는 이유가 있다. 둘을 각각 ApplicationRunner 로 두면
 * 계정 시드가 "이 tenant PK 는 남의 조직이라 건너뛴다" 고 판단해도 데이터 시드는 그걸 모른 채
 * 그 조직에 데모 alert 를 밀어넣는다. tenant 확보에 실패하면 데이터도 넣지 않아야 한다.
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
