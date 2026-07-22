package com.edrdog.api.auth;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * 세션 토큰 생성(순수). SecureRandom 32바이트를 base64url(패딩 없음)로 인코딩한다.
 */
public final class Tokens {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();

    private Tokens() {
    }

    public static String newToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return ENCODER.encodeToString(bytes);
    }
}
