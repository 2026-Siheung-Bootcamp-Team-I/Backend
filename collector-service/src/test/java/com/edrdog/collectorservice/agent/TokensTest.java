package com.edrdog.collectorservice.agent;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * node_key 발급/해시 검증. 저장은 해시만 하므로 같은 토큰이 늘 같은 64자리 16진수로 떨어져야
 * 매 요청 인증에서 행을 찾을 수 있다.
 */
class TokensTest {

    /** RFC 6234 의 "abc" 표준 벡터. 우리가 짠 계산이 진짜 SHA-256 인지 고정한다. */
    @Test
    void SHA_256_표준_벡터와_일치한다() {
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                Tokens.hash("abc"));
    }

    @Test
    void 해시는_소문자_64자리_16진수다() {
        String hash = Tokens.hash(Tokens.newToken());

        assertEquals(64, hash.length());
        assertTrue(hash.matches("[0-9a-f]{64}"), hash);
    }

    @Test
    void 같은_토큰은_같은_해시로_떨어진다() {
        String token = Tokens.newToken();

        assertEquals(Tokens.hash(token), Tokens.hash(token));
    }

    @Test
    void 다른_토큰은_다른_해시다() {
        assertNotEquals(Tokens.hash(Tokens.newToken()), Tokens.hash(Tokens.newToken()));
    }

    @Test
    void 발급_토큰은_매번_다르다() {
        assertNotEquals(Tokens.newToken(), Tokens.newToken());
    }
}
