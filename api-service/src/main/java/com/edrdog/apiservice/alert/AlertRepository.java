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

    /**
     * host 별 열린 alert 집계(엔드포인트 목록 status/위협수용). tenant 격리는 필수.
     * severity 리터럴은 detector 발행값(Alert.SEV_CRITICAL/SEV_HIGH)과 일치한다.
     */
    @Query("SELECT a.host AS host, COUNT(a) AS openTotal, "
            + "SUM(CASE WHEN a.severity = 'CRITICAL' THEN 1 ELSE 0 END) AS openCritical, "
            + "SUM(CASE WHEN a.severity = 'HIGH' THEN 1 ELSE 0 END) AS openHigh "
            + "FROM AlertRecord a WHERE a.tenantId = :tenantId AND a.status = :status "
            + "GROUP BY a.host")
    List<HostAlertCount> openAlertCountsByHost(@Param("tenantId") String tenantId,
                                               @Param("status") String status);

    /**
     * 기간 내 severity 별 카운트(대시보드 분포용). tenant 격리 필수, from/to 는 null 이면 무시한다.
     */
    @Query("SELECT a.severity AS severity, COUNT(a) AS cnt "
            + "FROM AlertRecord a WHERE a.tenantId = :tenantId "
            + "AND (:from is null or a.ts >= :from) "
            + "AND (:to is null or a.ts <= :to) "
            + "GROUP BY a.severity")
    List<SeverityCount> countBySeverity(@Param("tenantId") String tenantId,
                                        @Param("from") Long from,
                                        @Param("to") Long to);

    /**
     * 기간 내 ruleId 별 카운트(대시보드 카테고리 접기용). tenant 격리 필수, from/to 는 null 이면 무시한다.
     */
    @Query("SELECT a.ruleId AS ruleId, COUNT(a) AS cnt "
            + "FROM AlertRecord a WHERE a.tenantId = :tenantId "
            + "AND (:from is null or a.ts >= :from) "
            + "AND (:to is null or a.ts <= :to) "
            + "GROUP BY a.ruleId")
    List<RuleIdCount> countByRuleId(@Param("tenantId") String tenantId,
                                    @Param("from") Long from,
                                    @Param("to") Long to);

    /**
     * 기간 내 버킷(bucketMs 간격)×severity 별 카운트(대시보드 timeseries 용). tenant 격리 필수.
     * bucketStart = floor(ts / bucketMs) * bucketMs (UTC 정렬, TimeseriesFill.alignStart 와 동일 규칙).
     * JPQL 의 FLOOR 는 DB 방言 차이가 있어 native query 로 alerts 테이블에 직접 낸다(H2/MySQL 모두 지원).
     */
    @Query(value = "SELECT FLOOR(a.ts / :bucketMs) * :bucketMs AS bucketStart, a.severity AS severity, COUNT(*) AS cnt "
            + "FROM alerts a WHERE a.tenant_id = :tenantId AND a.ts >= :from AND a.ts < :to "
            + "GROUP BY FLOOR(a.ts / :bucketMs) * :bucketMs, a.severity",
            nativeQuery = true)
    List<TimeBucketSeverityCount> timeseries(@Param("tenantId") String tenantId,
                                             @Param("from") long from,
                                             @Param("to") long to,
                                             @Param("bucketMs") long bucketMs);
}
