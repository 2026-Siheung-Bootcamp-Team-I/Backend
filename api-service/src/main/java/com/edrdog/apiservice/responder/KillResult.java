package com.edrdog.apiservice.responder;

/**
 * responder-service kill 실행 결과(responder 의 ExecuteResult 와 동일 필드 사본).
 *
 * @param host        대상 호스트
 * @param target      대상 프로세스명/경로
 * @param status      KILLED | NO_MATCH | TIMEOUT | FAILED | COOLDOWN | DISABLED
 * @param executionId Fleet 실행 식별자 (없으면 null)
 */
public record KillResult(String host, String target, String status, String executionId) {
}
