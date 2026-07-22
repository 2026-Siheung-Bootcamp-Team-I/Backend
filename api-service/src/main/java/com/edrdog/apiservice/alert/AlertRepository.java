package com.edrdog.apiservice.alert;

import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

/**
 * alert 저장소. tenant 는 항상 필수 조건으로 강제해 조직 격리를 지킨다("A사는 A사 것만").
 * host/severity/status/from/to 는 옵션 필터로 null 이면 무시한다.
 */
public interface AlertRepository extends JpaRepository<AlertRecord, String> {

    @Query("SELECT a FROM AlertRecord a WHERE a.tenantId = :tenantId "
            + "AND (:host is null or a.host = :host) "
            + "AND (:severity is null or a.severity = :severity) "
            + "AND (:status is null or a.status = :status) "
            + "AND (:from is null or a.ts >= :from) "
            + "AND (:to is null or a.ts <= :to) "
            + "ORDER BY a.ts DESC")
    List<AlertRecord> search(@Param("tenantId") String tenantId,
                             @Param("host") String host,
                             @Param("severity") String severity,
                             @Param("status") String status,
                             @Param("from") Long from,
                             @Param("to") Long to,
                             Pageable pageable);
}
