package com.edrdog.collectorservice.agent.exception;

/**
 * 수집 API 인증 실패. collector 가 내는 인증 실패는 401 하나뿐이라 kind 구분을 두지 않는다.
 */
public class AuthException extends RuntimeException {

    public AuthException(String message) {
        super(message);
    }

    public static AuthException unauthorized(String message) {
        return new AuthException(message);
    }
}
