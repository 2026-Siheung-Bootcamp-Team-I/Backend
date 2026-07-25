package com.edrdog.apiservice.auth.service;

/**
 * 회원가입/로그인 성공 결과. 발급된 세션 토큰과 현재 유저 정보를 담는다.
 */
public record AuthResult(String token, Long userId, Long tenantId, String email, String role) {
}
