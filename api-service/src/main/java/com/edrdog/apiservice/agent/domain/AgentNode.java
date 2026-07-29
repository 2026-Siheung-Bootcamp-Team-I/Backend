package com.edrdog.apiservice.agent.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/**
 * enroll 성공한 에이전트 엔드포인트. node_key 로 tenant/host 를 되찾는 매핑이다.
 * node_key 는 발급 토큰 그대로를 PK 로 쓴다(추측 불가 랜덤).
 */
@Entity
@Table(name = "agent_nodes")
public class AgentNode {

    @Id
    @Column(length = 64)
    private String nodeKey;

    @Column(nullable = false)
    private Long tenantId;

    @Column(nullable = false)
    private String hostIdentifier;

    /** 에이전트가 보낸 runtime.GOOS 값(darwin/windows). 센서·감시 경로를 가르는 데 쓴다. */
    @Column
    private String platform;

    @Column(nullable = false)
    private Instant enrolledAt;

    @Column(nullable = false)
    private Instant lastSeenAt;

    protected AgentNode() {
    }

    private AgentNode(String nodeKey, Long tenantId, String hostIdentifier, String platform, Instant now) {
        this.nodeKey = nodeKey;
        this.tenantId = tenantId;
        this.hostIdentifier = hostIdentifier;
        this.platform = platform;
        this.enrolledAt = now;
        this.lastSeenAt = now;
    }

    public static AgentNode enroll(String nodeKey, Long tenantId, String hostIdentifier, String platform, Instant now) {
        return new AgentNode(nodeKey, tenantId, hostIdentifier, platform, now);
    }

    /** 인증된 요청(heartbeat/events 등) 수신 시각을 갱신(온라인 여부 관측용). */
    public void touch(Instant now) {
        this.lastSeenAt = now;
    }

    public String getNodeKey() {
        return nodeKey;
    }

    public Long getTenantId() {
        return tenantId;
    }

    public String getHostIdentifier() {
        return hostIdentifier;
    }

    public String getPlatform() {
        return platform;
    }

    public Instant getEnrolledAt() {
        return enrolledAt;
    }

    public Instant getLastSeenAt() {
        return lastSeenAt;
    }
}
