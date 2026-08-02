package com.edrdog.collectorservice.agent.web;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * 에이전트 enroll 요청. 프로토콜이 snake_case 라 필드마다 이름을 맞춘다.
 * platform 은 Go 의 {@code runtime.GOOS} 값 그대로(darwin/windows).
 */
public record EnrollRequest(
        @JsonProperty("enroll_secret") String enrollSecret,
        @JsonProperty("host_identifier") String hostIdentifier,
        @JsonProperty("platform") String platform,
        @JsonProperty("agent_version") String agentVersion
) {
}
