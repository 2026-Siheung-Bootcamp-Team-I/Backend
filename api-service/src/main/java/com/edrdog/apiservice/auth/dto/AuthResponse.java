package com.edrdog.apiservice.auth.dto;

import com.edrdog.apiservice.auth.service.AuthResult;

public record AuthResponse(String token, Long userId, Long tenantId, String email, String role) {

    public static AuthResponse from(AuthResult r) {
        return new AuthResponse(r.token(), r.userId(), r.tenantId(), r.email(), r.role());
    }
}
