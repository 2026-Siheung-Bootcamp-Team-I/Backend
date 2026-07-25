package com.edrdog.apiservice.demo;

import com.edrdog.apiservice.auth.repository.UserRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

/**
 * 데모 계정이 속한 tenant 를 찾는다. 데모 API 가 쓸 조직을 서버가 직접 결정하는 지점이다.
 *
 * <p>데모 API 는 로그인 토큰을 받지 않는다(발표자가 스웨거에서 토큰을 복사해 붙이는 건 실사용 흐름이 아니다).
 * 대신 이 조회 결과가 두 가지를 동시에 해결한다.
 *
 * <ul>
 *   <li>쓰기 대상 고정 — 발행되는 이벤트는 항상 데모 계정의 tenant 로만 태깅된다. 호출자가 tenant 를
 *       지정할 수 없으니 남의 조직 데이터에 섞일 경로가 없다.</li>
 *   <li>환경 게이팅 — 데모 계정은 시드({@code edrdog.demo.seed=true})로만 생긴다. 시드를 켠 적 없는
 *       환경에서는 여기서 empty 가 나와 API 가 아무 일도 하지 않는다.</li>
 * </ul>
 *
 * <p>PK 를 상수로 박지 않고 매번 조회하는 이유는, 데모 계정이 다른 tenant 에 붙어 있는 환경에서
 * 상수(99)를 그대로 쓰면 엉뚱한 조직에 이벤트를 넣게 되기 때문이다.
 */
@Component
public class DemoTenant {

    private final UserRepository users;

    public DemoTenant(UserRepository users) {
        this.users = users;
    }

    /** 데모 계정의 tenant PK 문자열. 계정이 없는 환경이면 empty. */
    @Transactional(readOnly = true)
    public Optional<String> resolve() {
        return users.findByEmail(DemoAccountSeeder.EMAIL)
                .map(user -> String.valueOf(user.getTenantId()));
    }
}
