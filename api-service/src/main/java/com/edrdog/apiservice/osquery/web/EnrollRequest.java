package com.edrdog.apiservice.osquery.web;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * osquery enroll 요청. osquery 는 snake_case 로 보낸다(enroll_secret/host_identifier/platform_type).
 * host_details 등 나머지 필드는 무시한다.
 */
public record EnrollRequest(
        @JsonProperty("enroll_secret") String enrollSecret,
        @JsonProperty("host_identifier") String hostIdentifier,
        @JsonProperty("platform_type") String platformType
) {
}
