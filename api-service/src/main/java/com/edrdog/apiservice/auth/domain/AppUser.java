package com.edrdog.apiservice.auth.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/**
 * 유저. "user"는 SQL 예약어라 클래스명은 AppUser, 테이블명은 users 로 둔다.
 */
@Entity
@Table(name = "users")
public class AppUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private String passwordHash;

    @Column(nullable = false)
    private Long tenantId;

    @Column(nullable = false)
    private String role;

    @Column(nullable = false)
    private Instant createdAt;

    @Column
    private String slackWebhookUrl;   // 유저 개인 알림 목적지 (자기 소유 host 탐지 알림 수신)

    protected AppUser() {
    }

    private AppUser(String email, String passwordHash, Long tenantId, String role, Instant createdAt) {
        this.email = email;
        this.passwordHash = passwordHash;
        this.tenantId = tenantId;
        this.role = role;
        this.createdAt = createdAt;
    }

    public static AppUser of(String email, String passwordHash, Long tenantId, String role, Instant createdAt) {
        return new AppUser(email, passwordHash, tenantId, role, createdAt);
    }

    public Long getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public Long getTenantId() {
        return tenantId;
    }

    public String getRole() {
        return role;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public String getSlackWebhookUrl() {
        return slackWebhookUrl;
    }

    /** 개인 Slack webhook URL 을 갱신한다. */
    public void updateWebhook(String url) {
        this.slackWebhookUrl = url;
    }
}
