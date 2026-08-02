package com.edrdog.apiservice.web;

import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;

/**
 * auth 밖에서 나는 예외를 {@code AuthExceptionHandler} 와 같은 {"error": 메시지} 본문으로 맞춘다.
 * 지금은 컨트롤러마다 따로 던져 어떤 경로는 Spring 기본 본문이, 어떤 경로는 우리 본문이 나가서
 * 프론트가 에러를 한 가지 방법으로 읽지 못한다.
 *
 * <p>{@link IllegalArgumentException} 은 일부러 받지 않는다. 잘못된 입력은 컨트롤러가
 * {@code AuthException.invalidInput} 으로 400 을 내고 있고, 그 검증을 지나쳐 빌더
 * ({@code TenantScope}, {@code QueryGuards})까지 간 것은 클라이언트가 고칠 수 없는 서버 버그다.
 * 통째로 400 으로 옮기면 서버 잘못이 클라이언트 잘못으로 기록되고 500 알람에서도 사라진다.
 */
// 상위 타입(Exception, RuntimeException)을 잡지 마라. advice 두 개 중 어느 것이 먼저 걸릴지는
// 순서에 달려 있어서, 상위 타입을 잡는 순간 AuthExceptionHandler 의 401/403 이 여기로 빨려 들어온다.
@RestControllerAdvice
public class ApiExceptionHandler {

    /** 컨트롤러가 status 를 직접 정해 던진 경우. status 는 그대로 두고 본문 모양만 맞춘다. */
    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<Map<String, String>> handle(ResponseStatusException e) {
        return body(e.getStatusCode(), e.getReason());
    }

    /** 필수 파라미터 누락과 타입 불일치. 상태코드는 Spring 기본과 같은 400 이고 본문만 통일한다. */
    @ExceptionHandler({MissingServletRequestParameterException.class, MethodArgumentTypeMismatchException.class})
    public ResponseEntity<Map<String, String>> handleBadParameter(Exception e) {
        return body(HttpStatus.BAD_REQUEST, parameterMessage(e));
    }

    private static String parameterMessage(Exception e) {
        if (e instanceof MissingServletRequestParameterException missing) {
            return "필수 파라미터가 없습니다: " + missing.getParameterName();
        }
        return "파라미터 형식이 올바르지 않습니다: " + ((MethodArgumentTypeMismatchException) e).getName();
    }

    // 사유가 빈 예외(없는 경로 404 등)는 상태 문구로 채운다. e.getMessage() 로 채우면
    // 요청 경로나 내부 타입 이름이 그대로 응답에 실려 나간다.
    private static ResponseEntity<Map<String, String>> body(HttpStatusCode status, String reason) {
        String message = reason != null && !reason.isBlank() ? reason : reasonPhrase(status);
        return ResponseEntity.status(status).body(Map.of("error", message));
    }

    private static String reasonPhrase(HttpStatusCode status) {
        HttpStatus resolved = HttpStatus.resolve(status.value());
        return resolved != null ? resolved.getReasonPhrase() : String.valueOf(status.value());
    }
}
