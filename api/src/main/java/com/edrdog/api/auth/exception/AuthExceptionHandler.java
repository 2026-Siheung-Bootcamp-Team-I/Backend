package com.edrdog.api.auth.exception;

import com.edrdog.api.auth.controller.AuthController;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

/**
 * AuthException 을 HTTP status + JSON 에러 본문으로 매핑한다.
 */
@RestControllerAdvice(assignableTypes = AuthController.class)
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
