package com.edrdog.apiservice.auth.web;

public record MeResponse(Long userId, Long tenantId, String email, String role) {
}
