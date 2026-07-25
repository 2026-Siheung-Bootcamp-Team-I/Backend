package com.edrdog.apiservice.notify.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

import java.time.Instant;

/**
 * host(엔드포인트) 소유권. 탐지 알림을 그 host 소유 유저의 개인 목적지로 라우팅하기 위한 매핑이다.
 * 같은 tenant 안에서 host 는 소유자 1명(unique(tenantId, host)). 유저가 자기 host 를 등록한다.
 */
@Entity
@Table(name = "host_owners", uniqueConstraints = @UniqueConstraint(columnNames = {"tenant_id", "host"}))
public class HostOwner {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "tenant_id", nullable = false)
    private Long tenantId;

    @Column(nullable = false)
    private String host;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected HostOwner() {
    }

    private HostOwner(Long tenantId, String host, Long userId, Instant createdAt) {
        this.tenantId = tenantId;
        this.host = host;
        this.userId = userId;
        this.createdAt = createdAt;
    }

    public static HostOwner of(Long tenantId, String host, Long userId, Instant createdAt) {
        return new HostOwner(tenantId, host, userId, createdAt);
    }

    public Long getId() {
        return id;
    }

    public Long getTenantId() {
        return tenantId;
    }

    public String getHost() {
        return host;
    }

    public Long getUserId() {
        return userId;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
