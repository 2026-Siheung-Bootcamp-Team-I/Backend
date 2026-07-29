package com.edrdog.apiservice.agent.web;

import com.fasterxml.jackson.annotation.JsonProperty;

/** enroll 성공 응답. 실패는 200 본문이 아니라 401 로 알린다. */
public record EnrollResponse(
        @JsonProperty("node_key") String nodeKey
) {
}
