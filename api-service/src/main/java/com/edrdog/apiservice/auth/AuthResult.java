package com.edrdog.apiservice.auth;

public record AuthResult(String token, Long userId, Long tenantId, String email, String role) {
}
