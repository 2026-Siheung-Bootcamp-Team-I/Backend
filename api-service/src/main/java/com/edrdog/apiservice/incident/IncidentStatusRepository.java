package com.edrdog.apiservice.incident;

import org.springframework.data.jpa.repository.JpaRepository;

/** 사건 트리아지 status 오버레이 저장소(MySQL). 사건 본체는 저장하지 않으므로 여기엔 트리아지된 id 만 있다. */
public interface IncidentStatusRepository extends JpaRepository<IncidentStatusRecord, String> {
}
