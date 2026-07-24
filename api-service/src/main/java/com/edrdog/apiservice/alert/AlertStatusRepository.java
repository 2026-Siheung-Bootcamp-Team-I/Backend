package com.edrdog.apiservice.alert;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

/**
 * 트리아지 status 오버레이 저장소(MySQL). 판정기록은 ClickHouse 라 여기엔 트리아지된 id 만 존재한다.
 * findByTenantId 는 tenant 의 트리아지된 id 전체(open 필터·host 집계에서 제외 목록으로 씀),
 * findAllById(상속)는 조회 결과 id 들의 status 를 한 번에 병합할 때 쓴다.
 */
public interface AlertStatusRepository extends JpaRepository<AlertStatusRecord, String> {

    List<AlertStatusRecord> findByTenantId(String tenantId);
}
