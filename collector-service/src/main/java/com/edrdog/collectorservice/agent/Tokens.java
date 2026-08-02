package com.edrdog.collectorservice.agent;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * node_key 발급(순수 랜덤)과 저장용 해시. 발급한 평문은 응답으로만 나가고 DB 에는 해시만 남는다.
 * DB 가 새도 그 값으로는 엔드포인트를 위장할 수 없어야 한다.
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

    /**
     * 저장·조회용 SHA-256 hex(소문자 64자). BCrypt 를 쓰지 않는 이유는 node_key 가 32바이트
     * SecureRandom 이라 사전공격 대상이 아니고, 매 요청 인증에 BCrypt 를 태우면 heartbeat/events
     * 경로가 그만큼 느려지기 때문이다.
     */
    public static String hash(String token) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(token.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                hex.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 을 쓸 수 없는 JVM", e);
        }
    }
}
