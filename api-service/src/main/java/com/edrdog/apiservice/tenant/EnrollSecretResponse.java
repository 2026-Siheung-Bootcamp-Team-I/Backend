package com.edrdog.apiservice.tenant;

/** enroll secret 발급/조회 응답. 미발급이면 enrollSecret 이 null. */
public record EnrollSecretResponse(Long tenantId, String enrollSecret) {
}
