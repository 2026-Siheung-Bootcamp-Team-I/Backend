package com.edrdog.api.auth.service;

/**
 * 토큰으로 확인된 현재 유저(토큰 제외). resolve 결과에 쓰인다.
 */
public record Principal(Long userId, Long tenantId, String email, String role) {
}
