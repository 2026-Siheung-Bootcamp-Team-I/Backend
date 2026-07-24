package com.edrdog.apiservice.demo;

import com.edrdog.apiservice.auth.domain.AppUser;
import com.edrdog.apiservice.auth.domain.Tenant;
import com.edrdog.apiservice.auth.repository.TenantRepository;
import com.edrdog.apiservice.auth.repository.UserRepository;
import jakarta.persistence.EntityManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;

/**
 * 발표용 데모 계정을 부팅 시 만든다. {@code edrdog.demo.seed=true} 일 때만 빈으로 올라온다.
 *
 * <p>가입 API(signup)로는 만들 수 없다. AuthValidation 이 이메일 형식과 8자 이상 비밀번호를 요구하기 때문이다.
 * 실제 가입 규칙을 느슨하게 푸는 대신 여기서 저장소에 직접 넣는다. 로그인(login)은 형식 검증 없이
 * 이메일로 조회만 하므로 {@code test} / {@code 1234} 로 그대로 로그인된다.
 *
 * <p>tenant PK 를 {@link #TENANT_ID} 로 고정하는 이유는 시나리오 발행 API 가 tenantId 를 직접 받기 때문이다.
 * 값이 고정이라야 발표 중에 {@code /api/auth/me} 로 PK 를 확인하는 단계를 건너뛸 수 있다.
 * PK 는 IDENTITY 라 JPA 로는 값을 지정할 수 없어 네이티브 INSERT 를 쓴다.
 */
@Component
@ConditionalOnProperty(name = "edrdog.demo.seed", havingValue = "true")
public class DemoAccountSeeder {

    /**
     * 발표 자료에 박아두는 고정 tenant PK. 가입으로 생기는 PK(1,2,3...)와 겹치지 않게 큰 값을 쓴다
     * (같은 DB 에서 실제 조직과 공존시키기 위해서다).
     */
    public static final long TENANT_ID = 99L;

    static final String EMAIL = "test";
    static final String PASSWORD = "1234";
    static final String TENANT_NAME = "데모 조직";
    static final String ROLE = "admin";

    private static final Logger log = LoggerFactory.getLogger(DemoAccountSeeder.class);

    private final EntityManager em;
    private final TenantRepository tenants;
    private final UserRepository users;
    private final BCryptPasswordEncoder encoder;

    public DemoAccountSeeder(EntityManager em, TenantRepository tenants,
                             UserRepository users, BCryptPasswordEncoder encoder) {
        this.em = em;
        this.tenants = tenants;
        this.users = users;
        this.encoder = encoder;
    }

    /**
     * 데모 tenant 와 계정을 보장한다.
     *
     * @return 데모 tenant 를 우리가 쓰고 있으면 true. 다른 조직이 PK 를 선점했으면 false
     *         (이 경우 호출자는 데이터 시드도 중단해야 한다. 남의 조직에 데모 데이터를 섞으면 안 된다)
     */
    @Transactional
    public boolean seed() {
        if (!ensureTenant()) {
            return false;
        }
        ensureUser();
        return true;
    }

    /**
     * 데모 tenant 를 보장한다. 이미 PK 가 쓰이고 있으면 덮지 않는다.
     *
     * @return 계정을 붙여도 되는 상태면 true. 남의 조직이 PK 를 쓰고 있으면 false.
     */
    private boolean ensureTenant() {
        Optional<Tenant> existing = tenants.findById(TENANT_ID);
        if (existing.isEmpty()) {
            em.createNativeQuery("INSERT INTO tenants (id, name, created_at) VALUES (:id, :name, :createdAt)")
                    .setParameter("id", TENANT_ID)
                    .setParameter("name", TENANT_NAME)
                    .setParameter("createdAt", Timestamp.from(Instant.now()))
                    .executeUpdate();
            log.info("데모 tenant 생성: id={} name={}", TENANT_ID, TENANT_NAME);
            return true;
        }
        if (!TENANT_NAME.equals(existing.get().getName())) {
            log.warn("tenant {} 가 이미 다른 조직({})이라 데모 계정 시드를 건너뜁니다. 데모 DB 인지 확인하세요.",
                    TENANT_ID, existing.get().getName());
            return false;
        }
        return true;
    }

    /** 데모 계정을 보장한다. 이미 있으면 비밀번호를 덮지 않는다. */
    private void ensureUser() {
        if (users.existsByEmail(EMAIL)) {
            log.info("데모 계정이 이미 있어 건너뜁니다: {}", EMAIL);
            return;
        }
        users.save(AppUser.of(EMAIL, encoder.encode(PASSWORD), TENANT_ID, ROLE, Instant.now()));
        log.info("데모 계정 생성: id={} / pw={} (tenantId={})", EMAIL, PASSWORD, TENANT_ID);
    }
}
