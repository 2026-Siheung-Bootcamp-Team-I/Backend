package com.edrdog.apiservice.auth;

public record Principal(Long userId, Long tenantId, String email, String role) {
}
