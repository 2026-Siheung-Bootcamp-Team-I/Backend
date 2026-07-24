package com.edrdog.apiservice.alert;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/**
 * 트리아지 status 오버레이(MySQL). 판정기록 자체(불변)는 ClickHouse 에 있고, 여기에는 가변인 status 만 둔다.
 * 행이 있으면 트리아지된 것(confirmed/false_positive), 없으면 open 으로 본다.
 * id 는 판정기록과 같은 결정적 값(AlertId)이라 두 저장소를 앱에서 병합할 수 있다.
 */
@Entity
@Table(name = "alert_status")
public class AlertStatusRecord {

    @Id
    private String id;

    @Column(name = "tenant_id", nullable = false)
    private String tenantId;

    @Column(nullable = false)
    private String status;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected AlertStatusRecord() {
    }

    private AlertStatusRecord(String id, String tenantId, String status, Instant updatedAt) {
        this.id = id;
        this.tenantId = tenantId;
        this.status = status;
        this.updatedAt = updatedAt;
    }

    /** 트리아지 오버레이 행 생성/갱신용. status 는 confirmed/false_positive 만 들어온다. */
    public static AlertStatusRecord of(String id, String tenantId, String status, Instant now) {
        return new AlertStatusRecord(id, tenantId, status, now);
    }

    public String getId() {
        return id;
    }

    public String getTenantId() {
        return tenantId;
    }

    public String getStatus() {
        return status;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }
}
