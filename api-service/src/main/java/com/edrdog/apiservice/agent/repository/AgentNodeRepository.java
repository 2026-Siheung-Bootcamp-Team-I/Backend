package com.edrdog.apiservice.agent.repository;

import com.edrdog.apiservice.agent.domain.AgentNode;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface AgentNodeRepository extends JpaRepository<AgentNode, String> {

    /** 같은 tenant 의 같은 host 재-enroll 시 노드를 재사용(무한 증식 방지). */
    Optional<AgentNode> findByTenantIdAndHostIdentifier(Long tenantId, String hostIdentifier);

    /** tenant 의 등록 노드 전체(호스트 목록 화면에서 events 와 병합하는 데 쓴다). */
    List<AgentNode> findByTenantId(Long tenantId);
}
