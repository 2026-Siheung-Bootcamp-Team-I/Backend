package com.edrdog.alertservice.dto;

import java.util.List;

/**
 * detector 가 alerts 토픽에 발행하는 판정 결과 (alert 모듈 소비용 사본).
 * 소비자는 자기 관점의 스키마 사본을 갖는다. 여분 필드는 JsonDeserializer 가 무시한다.
 *
 * @param tenantId 알림을 라우팅할 tenant 식별자 (tenant별 Slack webhook 조회 키).
 *                 detector 가 숫자 문자열로 발행한다(api-service 내부 조회 경로는 Long).
 * @param host     엔드포인트 식별자
 * @param ruleId   매칭된 룰 식별자 (예: SUSPICIOUS_PROCESS_CHAIN)
 * @param mitre    MITRE ATT&CK 기법 태그 (예: T1059)
 * @param severity 심각도: MEDIUM | HIGH | CRITICAL
 * @param action   권고 대응: notify | kill | isolate
 * @param ts       판정을 완성시킨 트리거 이벤트 시각 (epoch millis)
 * @param matched  판정 근거가 된 이벤트 요약들
 */
public record Alert(
        String tenantId,
        String host,
        String ruleId,
        String mitre,
        String severity,
        String action,
        long ts,
        List<String> matched
) {
    public static final String SEV_MEDIUM = "MEDIUM";
    public static final String SEV_HIGH = "HIGH";
    public static final String SEV_CRITICAL = "CRITICAL";

    public static final String ACTION_NOTIFY = "notify";
    public static final String ACTION_KILL = "kill";
    public static final String ACTION_ISOLATE = "isolate";
}
