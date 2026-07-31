package com.edrdog.apiservice.auth.dto;

public record MeResponse(Long userId, Long tenantId, String email, String role) {
}
