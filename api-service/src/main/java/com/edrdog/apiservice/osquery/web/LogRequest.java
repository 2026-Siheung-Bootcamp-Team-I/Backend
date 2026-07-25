package com.edrdog.apiservice.osquery.web;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;

/**
 * osquery log 요청. log_type 이 result 면 data 가 result-log 레코드 배열이다.
 * status 등 다른 로그는 data 스키마가 달라 수집 대상이 아니다.
 */
public record LogRequest(
        @JsonProperty("node_key") String nodeKey,
        @JsonProperty("log_type") String logType,
        @JsonProperty("data") JsonNode data
) {
    public boolean isResult() {
        return "result".equals(logType);
    }
}
