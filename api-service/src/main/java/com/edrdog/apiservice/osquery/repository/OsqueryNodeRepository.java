package com.edrdog.apiservice.osquery.repository;

import com.edrdog.apiservice.osquery.domain.OsqueryNode;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface OsqueryNodeRepository extends JpaRepository<OsqueryNode, String> {

    /** 같은 tenant 의 같은 host 재-enroll 시 노드를 재사용(무한 증식 방지). */
    Optional<OsqueryNode> findByTenantIdAndHostIdentifier(Long tenantId, String hostIdentifier);
}
