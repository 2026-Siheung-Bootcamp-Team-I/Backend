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
 * <p>enroll secret 을 그대로 링크에 싣지 않는 이유가 이 클래스가 있는 이유다. enroll secret 은
 * 테넌트당 하나이고 만료가 없어서, 링크가 한 번 새면 그 뒤로 아무나 그 테넌트에 에이전트를
 * 붙일 수 있다. 설치 토큰은 짧게 살고 따로 버릴 수 있다. 새어도 만료까지만 위험하다.
 *
 * <p>여러 대에 쓸 수 있게 둔다(일회용이 아니다). 실습실이나 팀 노트북처럼 한 번에 여러 대를
 * 까는 경우가 실제 쓰임이라, 일회용으로 만들면 기기마다 대시보드에 다시 들어가야 한다.
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
