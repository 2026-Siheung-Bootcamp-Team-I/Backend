package com.edrdog.apiservice.auth.domain;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 세션 만료 경계 판정(순수).
 */
class UserSessionTest {

    private final Instant expiresAt = Instant.parse("2026-01-01T00:00:00Z");
    private final UserSession session = UserSession.of("tok", 1L, 1L, expiresAt);

    @Test
    void 만료시각_이전이면_유효() {
        assertFalse(session.isExpired(expiresAt.minusSeconds(1)));
    }

    @Test
    void 만료시각_도달이나_이후면_만료() {
        assertTrue(session.isExpired(expiresAt));
        assertTrue(session.isExpired(expiresAt.plusSeconds(1)));
    }
}
