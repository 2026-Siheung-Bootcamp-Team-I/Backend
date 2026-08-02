package com.edrdog.collectorservice.agent.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/**
 * enroll 성공한 에이전트 엔드포인트. node_key 로 tenant/host 를 되찾는 매핑이다.
 * PK 는 발급 토큰의 SHA-256 해시다. 평문은 저장하지 않아 DB 가 새도 엔드포인트를 위장할 수 없다.
 */
@Entity
@Table(name = "agent_nodes")
public class AgentNode {

    @Id
    @Column(name = "node_key_hash", length = 64)
    private String nodeKeyHash;

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

    private AgentNode(String nodeKeyHash, Long tenantId, String hostIdentifier, String platform,
                      Instant enrolledAt, Instant lastSeenAt) {
        this.nodeKeyHash = nodeKeyHash;
        this.tenantId = tenantId;
        this.hostIdentifier = hostIdentifier;
        this.platform = platform;
        this.enrolledAt = enrolledAt;
        this.lastSeenAt = lastSeenAt;
    }

    public static AgentNode enroll(String nodeKeyHash, Long tenantId, String hostIdentifier, String platform, Instant now) {
        return new AgentNode(nodeKeyHash, tenantId, hostIdentifier, platform, now, now);
    }

    /** 재-enroll. 토큰이 바뀌면 PK 도 바뀌어 같은 행을 못 쓰므로 최초 등록 시각만 물려받아 새로 만든다. */
    public static AgentNode reenroll(String nodeKeyHash, AgentNode previous, String platform, Instant now) {
        return new AgentNode(nodeKeyHash, previous.tenantId, previous.hostIdentifier, platform,
                previous.enrolledAt, now);
    }

    /** 인증된 요청(heartbeat/events 등) 수신 시각을 갱신(온라인 여부 관측용). */
    public void touch(Instant now) {
        this.lastSeenAt = now;
    }

    public String getNodeKeyHash() {
        return nodeKeyHash;
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
