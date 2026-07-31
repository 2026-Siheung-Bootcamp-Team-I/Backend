package com.edrdog.apiservice.auth.service;

public record AuthResult(String token, Long userId, Long tenantId, String email, String role) {
}
