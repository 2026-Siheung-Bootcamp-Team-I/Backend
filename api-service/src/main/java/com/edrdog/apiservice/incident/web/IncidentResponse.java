package com.edrdog.apiservice.incident.web;

import com.edrdog.apiservice.alert.web.AlertResponse;
import com.edrdog.apiservice.alert.web.LineageResponse;

import java.util.List;

/**
 * 사건 조회/상세/트리아지 응답. 목록과 상세가 같은 형태를 쓰고, 무거운 것(alerts/lineage)만 상세에서 채운다.
 *
 * @param severity     구성 알림 중 가장 높은 것
 * @param rootProcess  사건이 시작된 프로세스명. 원본 이벤트를 못 찾았으면 빈 문자열이다(지어내지 않는다)
 * @param ruleIds      구성 알림의 rule (중복 제거, 시간순 첫 등장 순서)
 * @param threatNames  ruleIds 를 화면 표시용 한글로 옮긴 값(같은 순서)
 * @param alerts       구성 알림 전체(시간 오름차순). 목록에서는 null 이다
 * @param lineage      사건 체인의 이벤트로만 그린 계보 그래프. 목록에서는 null 이다
 */
public record IncidentResponse(
        String id,
        String host,
        String status,
        String severity,
        long firstTs,
        long lastTs,
        int alertCount,
        String rootProcess,
        List<String> ruleIds,
        List<String> threatNames,
        List<String> mitre,
        List<AlertResponse> alerts,
        LineageResponse lineage
) {
}
