package com.edrdog.api.auth.domain;

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
}
