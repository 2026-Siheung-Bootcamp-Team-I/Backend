package com.edrdog.api.auth.web;

/** 내 정보(/me) 응답. */
public record MeResponse(Long userId, Long tenantId, String email, String role) {
}
