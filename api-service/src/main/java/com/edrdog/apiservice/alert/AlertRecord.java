package com.edrdog.apiservice.alert;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * 적재된 alert (MySQL). status 가 트리아지로 바뀌므로 불변 이벤트 스토어(ClickHouse)가 아닌 MySQL 에 둔다.
 * id 는 tenantId|host|ruleId|ts 로 결정되어(AlertId) 재소비돼도 한 행만 남는다.
 */
@Entity
@Table(name = "alerts")
public class AlertRecord {

    @Id
    private String id;

    @Column(name = "tenant_id", nullable = false)
    private String tenantId;

    @Column(nullable = false)
    private String host;

    @Column(nullable = false)
    private String ruleId;

    @Column
    private String mitre;

    @Column
    private String severity;

    @Column
    private String action;

    @Column(nullable = false)
    private long ts;

    @Column(nullable = false)
    private String status;

    @ElementCollection(fetch = FetchType.LAZY)
    @CollectionTable(name = "alert_matched", joinColumns = @JoinColumn(name = "alert_id"))
    @Column(name = "line")
    @org.hibernate.annotations.BatchSize(size = 100)  // 목록 조회 시 matched N+1 완화(행별 SELECT → 배치 로딩)
    private List<String> matched = new ArrayList<>();

    @Column(nullable = false)
    private Instant createdAt;

    @Column(nullable = false)
    private Instant updatedAt;

    protected AlertRecord() {
    }

    private AlertRecord(String id, String tenantId, String host, String ruleId, String mitre,
                        String severity, String action, long ts, String status,
                        List<String> matched, Instant createdAt, Instant updatedAt) {
        this.id = id;
        this.tenantId = tenantId;
        this.host = host;
        this.ruleId = ruleId;
        this.mitre = mitre;
        this.severity = severity;
        this.action = action;
        this.ts = ts;
        this.status = status;
        this.matched = matched == null ? new ArrayList<>() : new ArrayList<>(matched);
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
    }

    /** 신규 적재용. status 는 항상 open 으로 시작한다. */
    public static AlertRecord open(String id, String tenantId, String host, String ruleId, String mitre,
                                   String severity, String action, long ts, List<String> matched, Instant now) {
        return new AlertRecord(id, tenantId, host, ruleId, mitre, severity, action, ts,
                AlertStatus.OPEN, matched, now, now);
    }

    /** 트리아지로 status 를 갱신한다. */
    public void triage(String status, Instant now) {
        this.status = status;
        this.updatedAt = now;
    }

    public String getId() {
        return id;
    }

    public String getTenantId() {
        return tenantId;
    }

    public String getHost() {
        return host;
    }

    public String getRuleId() {
        return ruleId;
    }

    public String getMitre() {
        return mitre;
    }

    public String getSeverity() {
        return severity;
    }

    public String getAction() {
        return action;
    }

    public long getTs() {
        return ts;
    }

    public String getStatus() {
        return status;
    }

    public List<String> getMatched() {
        return matched;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }
}
