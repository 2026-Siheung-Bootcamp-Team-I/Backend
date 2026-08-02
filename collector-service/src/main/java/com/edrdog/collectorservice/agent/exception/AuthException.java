package com.edrdog.collectorservice.agent.exception;

/** 수집 API 인증 실패(401). */
public class AuthException extends RuntimeException {

    public AuthException(String message) {
        super(message);
    }

    public static AuthException unauthorized(String message) {
        return new AuthException(message);
    }
}
