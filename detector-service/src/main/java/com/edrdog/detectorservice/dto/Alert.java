package com.edrdog.detectorservice.dto;

import java.util.List;

/**
 * 상관분석 판정 결과 (alerts 토픽 발행 스키마).
 *
 * @param host     엔드포인트 식별자
 * @param ruleId   매칭된 룰 식별자 (예: SUSPICIOUS_PROCESS_CHAIN)
 * @param mitre    MITRE ATT&CK 기법 태그 (예: T1059)
 * @param severity 심각도: HIGH | CRITICAL
 * @param action   권고 대응: notify | kill | isolate (severity 매핑)
 * @param ts       판정을 완성시킨 트리거 이벤트 시각 (epoch millis)
 * @param matched  판정 근거가 된 이벤트 요약들
 * @param tenantId 조직(tenant) 식별자 — 트리거 이벤트에서 물려받은 격리 태그
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
    public static final String SEV_HIGH = "HIGH";
    public static final String SEV_CRITICAL = "CRITICAL";

    public static final String ACTION_NOTIFY = "notify";
    public static final String ACTION_KILL = "kill";
    public static final String ACTION_ISOLATE = "isolate";

    /** severity → 권고 대응 매핑. CRITICAL 은 격리, HIGH 는 프로세스 종료, 그 외는 알림. */
    public static String actionFor(String severity) {
        return switch (severity) {
            case SEV_CRITICAL -> ACTION_ISOLATE;
            case SEV_HIGH -> ACTION_KILL;
            default -> ACTION_NOTIFY;
        };
    }
}
