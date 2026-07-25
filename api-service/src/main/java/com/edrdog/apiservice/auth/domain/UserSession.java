package com.edrdog.apiservice.auth.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/**
 * 세션. opaque 랜덤 토큰을 PK 로 저장하고, 로그아웃 시 삭제로 무효화한다.
 */
@Entity
@Table(name = "sessions")
public class UserSession {

    @Id
    private String token;

    @Column(nullable = false)
    private Long userId;

    @Column(nullable = false)
    private Long tenantId;

    @Column(nullable = false)
    private Instant expiresAt;

    protected UserSession() {
    }

    private UserSession(String token, Long userId, Long tenantId, Instant expiresAt) {
        this.token = token;
        this.userId = userId;
        this.tenantId = tenantId;
        this.expiresAt = expiresAt;
    }

    public static UserSession of(String token, Long userId, Long tenantId, Instant expiresAt) {
        return new UserSession(token, userId, tenantId, expiresAt);
    }

    /** 주어진 시각 기준으로 만료됐는지(경계 포함: expiresAt 도달 시 만료). */
    public boolean isExpired(Instant now) {
        return !now.isBefore(expiresAt);
    }

    public String getToken() {
        return token;
    }

    public Long getUserId() {
        return userId;
    }

    public Long getTenantId() {
        return tenantId;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }
}
