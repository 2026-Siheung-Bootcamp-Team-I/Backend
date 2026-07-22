package com.edrdog.apiservice.auth.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

/**
 * AuthException 을 HTTP status + JSON 에러 본문으로 매핑한다.
 * auth 컨트롤러뿐 아니라 조회 컨트롤러(세션 Bearer 로 tenant 를 뽑는 EventQueryController)의
 * 토큰 검증 실패(401)도 여기서 일관되게 처리하도록 전역으로 둔다.
 */
@RestControllerAdvice
public class AuthExceptionHandler {

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<Map<String, String>> handle(AuthException e) {
        HttpStatus status = switch (e.getKind()) {
            case INVALID_INPUT -> HttpStatus.BAD_REQUEST;
            case UNAUTHORIZED -> HttpStatus.UNAUTHORIZED;
            case DUPLICATE -> HttpStatus.CONFLICT;
        };
        return ResponseEntity.status(status).body(Map.of("error", e.getMessage()));
    }
}
