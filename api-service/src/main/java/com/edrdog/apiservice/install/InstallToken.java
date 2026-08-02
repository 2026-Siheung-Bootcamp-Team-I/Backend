package com.edrdog.apiservice.install;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/**
 * 설치 링크 토큰. 대시보드가 발급하고, 엔드포인트가 설치 스크립트를 받을 때 제시한다.
 *
 * <p>만료(expiresAt)가 이 토큰의 방어선이다. 수명을 늘리면 새었을 때 위험한 기간이 그대로 늘어난다.
 * <p>일회용이 아니다. 한 토큰으로 여러 대를 깔라고 둔 것이라, 1회 소진으로 바꾸면 기기마다 대시보드에 다시 들어가야 한다.
 */
@Entity
@Table(name = "install_tokens")
public class InstallToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String token;

    @Column(nullable = false)
    private Long tenantId;

    @Column(nullable = false)
    private Instant expiresAt;

    @Column(nullable = false)
    private Instant createdAt;

    protected InstallToken() {
    }

    private InstallToken(String token, Long tenantId, Instant createdAt, Instant expiresAt) {
        this.token = token;
        this.tenantId = tenantId;
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
    }

    public static InstallToken of(String token, Long tenantId, Instant createdAt, Instant expiresAt) {
        return new InstallToken(token, tenantId, createdAt, expiresAt);
    }

    public Long getId() {
        return id;
    }

    public String getToken() {
        return token;
    }

    public Long getTenantId() {
        return tenantId;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    /** 기준 시각에 아직 살아 있는지. 만료 시각과 같은 순간은 이미 죽은 것으로 본다. */
    public boolean isAliveAt(Instant now) {
        return now.isBefore(expiresAt);
    }
}
