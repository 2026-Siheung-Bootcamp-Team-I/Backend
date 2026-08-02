package com.edrdog.collectorservice.agent.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

/**
 * AuthException 을 401 + JSON 에러 본문으로 매핑한다.
 * 에이전트는 이 401 을 보고 저장한 node_key 를 버린 뒤 다시 등록한다.
 */
@RestControllerAdvice
public class AuthExceptionHandler {

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<Map<String, String>> handle(AuthException e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", e.getMessage()));
    }
}
