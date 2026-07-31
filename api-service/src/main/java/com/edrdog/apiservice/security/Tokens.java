package com.edrdog.apiservice.security;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * 인증 토큰 생성(순수 랜덤). enroll secret(테넌트가 엔드포인트에 배포)과
 * node_key(enroll 성공 시 발급) 둘 다 추측 불가한 URL-safe 랜덤 문자열이면 된다.
 *
 * <p>수집(agent)과 테넌트 관리(tenant) 양쪽이 같은 규칙으로 토큰을 만들어야 해서
 * 어느 한쪽 패키지에 두지 않고 security 에 둔다.
 */
public final class Tokens {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final int BYTES = 32;

    private Tokens() {
    }

    /** 충돌 확률 무시 가능. */
    public static String newToken() {
        byte[] buf = new byte[BYTES];
        RANDOM.nextBytes(buf);
        return ENCODER.encodeToString(buf);
    }
}
