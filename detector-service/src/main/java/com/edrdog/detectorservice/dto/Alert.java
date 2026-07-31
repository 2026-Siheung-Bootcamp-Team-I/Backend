package com.edrdog.detectorservice.dto;

import java.util.List;

/**
 * 상관분석 판정 결과 (alerts 토픽 발행 스키마).
 *
 * @param host     엔드포인트 식별자
 * @param ruleId   매칭된 룰 식별자 (예: SUSPICIOUS_PROCESS_CHAIN)
 * @param mitre    MITRE ATT&CK 기법 태그 (예: T1059)
 * @param severity 심각도: MEDIUM | HIGH | CRITICAL
 * @param action   권고 대응: notify | kill | isolate (severity 매핑)
 * @param ts       판정을 완성시킨 트리거 이벤트 시각 (epoch millis)
 * @param matched  판정 근거가 된 이벤트 요약들
 * @param tenantId 조직(tenant) 식별자 — 트리거 이벤트에서 물려받은 격리 태그
 * @param target   조치 대상 프로세스명/경로 — responder 의 kill 실행에 사용 (kill 대상 없으면 null)
 * @param domain   이 알림과 관련된 목적지 도메인 (관측 못했으면 빈 문자열). 판정 근거 중 목적지를 관측한
 *                 이벤트에서 가져오며, 트리거와 같은 이벤트가 아닐 수 있다(R2 는 다운로드와 실행을 상관한다).
 * @param destIp   이 알림과 관련된 목적지 IP (관측 못했으면 빈 문자열). 출처는 domain 과 같다.
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
        String target,
        String domain,
        String destIp
) {
    public static final String SEV_MEDIUM = "MEDIUM";
    public static final String SEV_HIGH = "HIGH";
    public static final String SEV_CRITICAL = "CRITICAL";

    public static final String ACTION_NOTIFY = "notify";
    public static final String ACTION_KILL = "kill";
    public static final String ACTION_ISOLATE = "isolate";

    /**
     * severity → 권고 대응 매핑. CRITICAL/HIGH 는 프로세스 종료, 그 외는 알림.
     *
     * <p>CRITICAL 을 격리로 권고했었는데 격리는 구현이 없다. responder 가 할 수 있는 건 종료뿐이다.
     * 권고와 실제 조치가 다르면 사용자가 격리된 줄 알고 넘어간다. 있는 기능으로 권고를 맞춘다.
     * 격리를 실제로 붙이면(방화벽 차단 등) 그때 CRITICAL 을 되돌린다.
     */
    public static String actionFor(String severity) {
        return switch (severity) {
            case SEV_CRITICAL, SEV_HIGH -> ACTION_KILL;
            default -> ACTION_NOTIFY;
        };
    }
}
