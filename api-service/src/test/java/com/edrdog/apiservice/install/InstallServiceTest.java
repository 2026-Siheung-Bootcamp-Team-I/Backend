package com.edrdog.apiservice.install;

import com.edrdog.apiservice.auth.exception.AuthException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * InstallService: 설치 토큰 발급과 해석. 리포지토리는 목킹한다.
 */
class InstallServiceTest {

    private static final Instant NOW = Instant.parse("2026-07-31T00:00:00Z");
    private static final Duration TTL = Duration.ofHours(24);

    private InstallTokenRepository tokens;
    private InstallService service;

    @BeforeEach
    void setUp() {
        tokens = mock(InstallTokenRepository.class);
        when(tokens.save(any(InstallToken.class))).thenAnswer(i -> i.getArgument(0));
        service = new InstallService(tokens, TTL);
    }

    @Test
    void 발급하면_수명만큼_뒤에_만료된다() {
        InstallToken t = service.issue(7L, NOW);

        assertEquals(7L, t.getTenantId());
        assertEquals(NOW.plus(TTL), t.getExpiresAt());
        assertTrue(t.getToken().length() >= 32, "토큰이 너무 짧다: " + t.getToken());
    }

    @Test
    void 발급할_때마다_다른_토큰이_나온다() {
        assertNotEquals(service.issue(7L, NOW).getToken(), service.issue(7L, NOW).getToken());
    }

    @Test
    void 살아있는_토큰은_테넌트를_돌려준다() {
        when(tokens.findByToken("tok")).thenReturn(Optional.of(alive()));

        assertEquals(7L, service.resolve("tok", NOW));
    }

    @Test
    void 만료된_토큰은_거부한다() {
        when(tokens.findByToken("tok")).thenReturn(Optional.of(alive()));

        // 만료 시각 그 순간부터 죽은 것으로 본다.
        assertThrows(AuthException.class, () -> service.resolve("tok", NOW.plus(TTL)));
        assertThrows(AuthException.class, () -> service.resolve("tok", NOW.plus(TTL).plusSeconds(1)));
    }

    @Test
    void 모르는_토큰은_거부한다() {
        when(tokens.findByToken(any())).thenReturn(Optional.empty());

        assertThrows(AuthException.class, () -> service.resolve("없는토큰", NOW));
    }

    @Test
    void 만료된_토큰과_모르는_토큰은_같은_오류를_준다() {
        // 오류를 갈라 주면 남의 토큰이 존재하는지 아닌지를 밖에서 알아낼 수 있다.
        when(tokens.findByToken("만료")).thenReturn(Optional.of(alive()));
        when(tokens.findByToken("없음")).thenReturn(Optional.empty());

        AuthException expired = assertThrows(AuthException.class, () -> service.resolve("만료", NOW.plus(TTL)));
        AuthException unknown = assertThrows(AuthException.class, () -> service.resolve("없음", NOW));

        assertEquals(unknown.getMessage(), expired.getMessage());
    }

    private static InstallToken alive() {
        return InstallToken.of("tok", 7L, NOW, NOW.plus(TTL));
    }
}
