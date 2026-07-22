package com.edrdog.apiservice.alert.dto;

import java.util.List;

/**
 * alerts 토픽 소비 스키마 사본 (detector 발행 Alert 와 동일 필드).
 * api-service 는 이 값을 자기 MySQL 에 적재해 조회/트리아지 API 로 서빙한다.
 *
 * @param host     엔드포인트 식별자
 * @param ruleId   매칭된 룰 식별자
 * @param mitre    MITRE ATT&CK 기법 태그
 * @param severity 심각도
 * @param action   권고 대응
 * @param ts       판정 시각 (epoch millis)
 * @param matched  판정 근거 이벤트 요약들
 * @param tenantId 조직(tenant) 식별자 (문자열)
 */
public record Alert(
        String host,
        String ruleId,
        String mitre,
        String severity,
        String action,
        long ts,
        List<String> matched,
        String tenantId
) {
}
