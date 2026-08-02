package com.edrdog.apiservice.demo;

import com.edrdog.apiservice.auth.AppUser;
import com.edrdog.apiservice.auth.Tenant;
import com.edrdog.apiservice.auth.TenantRepository;
import com.edrdog.apiservice.auth.UserRepository;
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
 * 발표용 데모 계정을 부팅 시 만든다.
 * 조건부 빈을 풀면 운영 DB 에도 비밀번호 1234 짜리 계정이 생긴다({@code edrdog.demo.seed} 가 그걸 막는 유일한 장치다).
 * 가입 API 의 형식 검증(AuthValidation)을 통과하지 못하는 계정이라 저장소에 직접 넣고,
 * tenant PK 는 IDENTITY 라 JPA 로 지정할 수 없어 네이티브 INSERT 를 쓴다.
 */
@Component
@ConditionalOnProperty(name = "edrdog.demo.seed", havingValue = "true")
public class DemoAccountSeeder {

    /** 발표 자료에 박아두는 고정 tenant PK. 작은 값으로 내리면 가입으로 생기는 PK(1,2,3...)와 부딪힌다. */
    public static final long TENANT_ID = 99L;

    /** 데모 계정 이메일. 데모 API 가 이 계정으로 쓸 tenant 를 찾는다(DemoTenant). */
    public static final String EMAIL = "test@edrdog.local";

    /** 이메일 형식이 아니던 옛 데모 계정. 남아 있으면 정리한다. */
    static final String LEGACY_EMAIL = "test";
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
     *         (호출자는 이때 데이터 시드도 중단해야 한다. 남의 조직에 데모 데이터를 섞으면 안 된다)
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
        users.findByEmail(LEGACY_EMAIL).ifPresent(legacy -> {
            users.delete(legacy);
            log.info("이메일 형식이 아니던 옛 데모 계정 정리: {}", LEGACY_EMAIL);
        });
        if (users.existsByEmail(EMAIL)) {
            log.info("데모 계정이 이미 있어 건너뜁니다: {}", EMAIL);
            return;
        }
        users.save(AppUser.of(EMAIL, encoder.encode(PASSWORD), TENANT_ID, ROLE, Instant.now()));
        log.info("데모 계정 생성: id={} / pw={} (tenantId={})", EMAIL, PASSWORD, TENANT_ID);
    }
}
