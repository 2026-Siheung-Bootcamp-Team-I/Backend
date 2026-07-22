package com.edrdog.apiservice.auth.exception;

/**
 * 인증/회원가입 실패를 나타내는 예외. kind 로 HTTP status 매핑을 구분한다.
 */
public class AuthException extends RuntimeException {

    public enum Kind {
        INVALID_INPUT,  // 400
        UNAUTHORIZED,   // 401
        DUPLICATE       // 409
    }

    private final Kind kind;

    public AuthException(Kind kind, String message) {
        super(message);
        this.kind = kind;
    }

    public Kind getKind() {
        return kind;
    }

    public static AuthException invalidInput(String message) {
        return new AuthException(Kind.INVALID_INPUT, message);
    }

    public static AuthException unauthorized(String message) {
        return new AuthException(Kind.UNAUTHORIZED, message);
    }

    public static AuthException duplicate(String message) {
        return new AuthException(Kind.DUPLICATE, message);
    }
}
