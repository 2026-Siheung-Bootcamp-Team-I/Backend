package com.edrdog.responderservice.response;

/**
 * 실제 조치 실행 결과(트리거 API 응답).
 *
 * @param host        대상 호스트
 * @param target      대상 프로세스명/경로
 * @param status      KILLED | NO_MATCH | TIMEOUT | FAILED | COOLDOWN | DISABLED
 * @param executionId Fleet 실행 식별자 (없으면 null)
 */
public record ExecuteResult(String host, String target, String status, String executionId) {
}
