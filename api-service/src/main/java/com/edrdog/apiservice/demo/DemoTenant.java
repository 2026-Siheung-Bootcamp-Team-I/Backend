package com.edrdog.apiservice.demo;

import com.edrdog.apiservice.auth.UserRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

/**
 * 데모 계정이 속한 tenant 를 찾는다. 인증 없는 데모 API 가 쓸 조직을 서버가 직접 결정하는 지점이다.
 * 이 조회가 쓰기 대상을 데모 tenant 로 못 박고, 시드를 켠 적 없는 환경에서는 empty 로 API 를 무력화한다.
 * PK 상수(99)를 대신 박으면 데모 계정이 다른 tenant 에 붙어 있는 환경에서 엉뚱한 조직에 이벤트를 넣는다.
 */
@Component
public class DemoTenant {

    private final UserRepository users;

    public DemoTenant(UserRepository users) {
        this.users = users;
    }

    @Transactional(readOnly = true)
    public Optional<String> resolve() {
        return users.findByEmail(DemoAccountSeeder.EMAIL)
                .map(user -> String.valueOf(user.getTenantId()));
    }
}
