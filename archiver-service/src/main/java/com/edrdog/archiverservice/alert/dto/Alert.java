package com.edrdog.archiverservice.alert.dto;

import java.util.List;

/**
 * alerts 토픽 소비 스키마 사본 (detector 발행 Alert 와 동일 필드, api-service dto.Alert 사본).
 * archiver 는 이 값을 ClickHouse(판정기록)에 적재만 한다(조회·트리아지는 api-service 담당).
 *
 * @param ts       판정 시각 (epoch millis)
 * @param tenantId 조직(tenant) 식별자 (문자열)
 * @param domain   이 알림과 관련된 목적지 도메인 (판정 근거 중 관측된 것, 없으면 빈 문자열)
 * @param destIp   이 알림과 관련된 목적지 IP (출처는 domain 과 같다)
 */
public record Alert(
        String host,
        String ruleId,
        String mitre,
        String severity,
        String action,
        long ts,
        List<String> matched,
        String tenantId,
        String domain,
        String destIp
) {
}
