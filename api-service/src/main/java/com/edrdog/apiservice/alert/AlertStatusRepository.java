package com.edrdog.apiservice.alert;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

/**
 * 트리아지 status 오버레이 저장소(MySQL). 판정기록은 ClickHouse 라 여기엔 트리아지된 id 만 존재한다.
 */
public interface AlertStatusRepository extends JpaRepository<AlertStatusRecord, String> {

    List<AlertStatusRecord> findByTenantId(String tenantId);
}
