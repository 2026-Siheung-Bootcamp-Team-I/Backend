package com.edrdog.apiservice.install;

import com.edrdog.apiservice.auth.exception.AuthException;
import com.edrdog.apiservice.security.Tokens;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;

/**
 * 설치 링크 토큰의 발급과 해석.
 *
 * <p>시각을 인자로 받는다. 만료는 이 클래스의 핵심 규칙인데 {@code Instant.now()} 를 안에서
 * 부르면 그 규칙을 테스트로 고정할 수가 없다.
 */
@Service
public class InstallService {

    private final InstallTokenRepository tokens;
    private final Duration ttl;

    // 생성자가 둘이라 어느 쪽으로 만들지 명시해야 한다. 안 붙이면 Spring 이 기본 생성자를
    // 찾다가 부팅 자체가 실패한다.
    @Autowired
    public InstallService(InstallTokenRepository tokens,
                          @Value("${edrdog.install.token-ttl-hours:24}") long ttlHours) {
        this(tokens, Duration.ofHours(ttlHours));
    }

    /** 테스트용. 수명을 직접 넣어 만료 규칙을 고정한다. */
    InstallService(InstallTokenRepository tokens, Duration ttl) {
        this.tokens = tokens;
        this.ttl = ttl;
    }

    /** 설치 토큰을 새로 발급한다. */
    @Transactional
    public InstallToken issue(Long tenantId, Instant now) {
        return tokens.save(InstallToken.of(Tokens.newToken(), tenantId, now, now.plus(ttl)));
    }

    /**
     * 설치 토큰으로 테넌트를 찾는다. 없거나 만료면 404.
     *
     * <p>없는 것과 만료된 것을 같은 오류로 돌려준다. 갈라 주면 토큰을 넣어 보는 것만으로
     * 그게 존재했던 값인지 아닌지를 밖에서 알아낼 수 있다.
     */
    @Transactional(readOnly = true)
    public Long resolve(String token, Instant now) {
        return tokens.findByToken(token)
                .filter(t -> t.isAliveAt(now))
                .map(InstallToken::getTenantId)
                .orElseThrow(() -> AuthException.notFound("설치 링크가 없거나 만료되었습니다"));
    }

    public Duration ttl() {
        return ttl;
    }
}
