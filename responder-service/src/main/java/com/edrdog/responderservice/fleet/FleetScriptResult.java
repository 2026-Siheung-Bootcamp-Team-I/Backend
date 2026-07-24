package com.edrdog.responderservice.fleet;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Fleet `POST /scripts/run/sync` 응답 (필요한 필드만).
 * exit_code 는 스크립트가 아직 안 끝났으면 null 로 온다.
 *
 * @param executionId Fleet 실행 식별자
 * @param exitCode    스크립트 종료 코드 (미완료면 null)
 * @param hostTimeout 호스트가 제한시간 내 응답 못 함
 * @param output      스크립트 표준출력
 * @param message     Fleet 측 메시지 (오류 등)
 */
public record FleetScriptResult(
        @JsonProperty("execution_id") String executionId,
        @JsonProperty("exit_code") Integer exitCode,
        @JsonProperty("host_timeout") boolean hostTimeout,
        String output,
        String message
) {
}
