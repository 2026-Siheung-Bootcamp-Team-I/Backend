package com.edrdog.apiservice.tenant;

/** collector 가 enroll 검증 때 보내는 본문. 에이전트 설정의 enroll_secret 그대로다. */
public record ResolveTenantRequest(String enrollSecret) {
}
