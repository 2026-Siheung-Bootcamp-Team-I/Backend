package com.edrdog.apiservice.agent.web;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * 명령 실행 결과 보고. 에이전트가 쓰는 status 는 KILLED/NO_MATCH/FAILED 셋뿐이다.
 * TIMEOUT/COOLDOWN/DISABLED 는 엔드포인트가 판단할 수 없어 서버(responder)가 붙인다.
 */
public record CommandResultRequest(
        @JsonProperty("command_id") String commandId,
        @JsonProperty("status") String status,
        @JsonProperty("message") String message
) {
}
