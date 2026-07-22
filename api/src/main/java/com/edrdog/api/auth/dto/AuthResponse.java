package com.edrdog.api.auth.dto;

import com.edrdog.api.auth.service.AuthResult;

/** 회원가입/로그인 응답. 세션 토큰과 유저 정보를 담는다. */
public record AuthResponse(String token, Long userId, Long tenantId, String email, String role) {

    public static AuthResponse from(AuthResult r) {
        return new AuthResponse(r.token(), r.userId(), r.tenantId(), r.email(), r.role());
    }
}
