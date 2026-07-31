package com.edrdog.apiservice.auth.service;

public record Principal(Long userId, Long tenantId, String email, String role) {
}
