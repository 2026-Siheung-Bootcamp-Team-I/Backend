package com.edrdog.apiservice.tenant;

/** 미발급이면 enrollSecret 이 null. */
public record EnrollSecretResponse(Long tenantId, String enrollSecret) {
}
