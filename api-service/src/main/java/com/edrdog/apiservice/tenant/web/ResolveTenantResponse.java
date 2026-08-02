package com.edrdog.apiservice.tenant.web;

/** enroll secret 이 가리키는 tenant PK. 매칭이 없으면 이 본문 대신 404 다. */
public record ResolveTenantResponse(Long tenantId) {
}
