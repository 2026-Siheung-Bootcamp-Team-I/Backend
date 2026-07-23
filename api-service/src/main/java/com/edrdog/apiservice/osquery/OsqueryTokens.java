package com.edrdog.apiservice.osquery;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * osquery 인증 토큰 생성(순수 랜덤). enroll secret(테넌트가 엔드포인트에 배포)과
 * node_key(enroll 성공 시 발급) 둘 다 추측 불가한 URL-safe 랜덤 문자열이면 된다.
 */
public final class OsqueryTokens {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final int BYTES = 32;

    private OsqueryTokens() {
    }

    /** 32바이트 랜덤을 URL-safe base64(패딩 없음)로. 충돌 확률 무시 가능. */
    public static String newToken() {
        byte[] buf = new byte[BYTES];
        RANDOM.nextBytes(buf);
        return ENCODER.encodeToString(buf);
    }
}
