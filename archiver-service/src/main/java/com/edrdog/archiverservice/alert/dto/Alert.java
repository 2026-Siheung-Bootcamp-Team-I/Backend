package com.edrdog.archiverservice.alert.dto;

import java.util.List;

/**
 * alerts 토픽 소비 스키마 사본 (detector 발행 Alert 와 동일 필드, api-service dto.Alert 사본).
 *
 * @param ts       판정 시각 (epoch millis)
 * @param tenantId 조직(tenant) 식별자 (문자열)
 * @param domain   이 알림과 관련된 목적지 도메인 (없으면 빈 문자열)
 * @param destIp   이 알림과 관련된 목적지 IP
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
