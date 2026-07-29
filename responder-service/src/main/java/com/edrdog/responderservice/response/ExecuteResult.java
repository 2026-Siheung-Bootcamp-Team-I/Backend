package com.edrdog.responderservice.response;

/**
 * 실제 조치 실행 결과(트리거 API 응답).
 *
 * @param host        대상 호스트
 * @param target      대상 프로세스명/경로
 * @param status      KILLED | NO_MATCH | TIMEOUT | FAILED | COOLDOWN | DISABLED
 * @param executionId 명령 식별자 (실행 전에 끝난 DISABLED/COOLDOWN 이면 null).
 *                    api-service 의 KillResult 가 이 이름으로 받고 있어 필드명은 그대로 둔다
 */
public record ExecuteResult(String host, String target, String status, String executionId) {
}
