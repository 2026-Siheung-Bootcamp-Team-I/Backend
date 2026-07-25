package com.edrdog.apiservice.auth.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/**
 * 조직(테넌트). 회원가입 시 유저마다 하나 생성한다.
 */
@Entity
@Table(name = "tenants")
public class Tenant {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private Instant createdAt;

    @Column
    private String slackWebhookUrl;

    @Column(unique = true)
    private String enrollSecret;   // osquery 엔드포인트가 enroll 시 제출하는 테넌트 배포 시크릿

    protected Tenant() {
    }

    private Tenant(String name, Instant createdAt) {
        this.name = name;
        this.createdAt = createdAt;
    }

    public static Tenant of(String name, Instant createdAt) {
        return new Tenant(name, createdAt);
    }

    public Long getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public String getSlackWebhookUrl() {
        return slackWebhookUrl;
    }

    /** Slack webhook URL 을 갱신한다. */
    public void updateWebhook(String url) {
        this.slackWebhookUrl = url;
    }

    public String getEnrollSecret() {
        return enrollSecret;
    }

    /** enroll secret 을 발급/회전한다. */
    public void updateEnrollSecret(String secret) {
        this.enrollSecret = secret;
    }
}
