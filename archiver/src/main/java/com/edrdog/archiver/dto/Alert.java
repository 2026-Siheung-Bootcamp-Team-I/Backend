package com.edrdog.archiver.dto;

import java.util.List;

/**
 * detector 가 alerts 토픽에 발행하는 판정 결과 (archiver 소비용 사본).
 * 소비자는 자기 관점의 스키마 사본을 갖는다. 여분 필드는 JsonDeserializer 가 무시한다.
 *
 * @param host     엔드포인트 식별자
 * @param ruleId   매칭된 룰 식별자 (예: SUSPICIOUS_PROCESS_CHAIN)
 * @param mitre    MITRE ATT&CK 기법 태그 (예: T1059)
 * @param severity 심각도: HIGH | CRITICAL
 * @param action   권고 대응: notify | kill | isolate
 * @param ts       판정을 완성시킨 트리거 이벤트 시각 (epoch millis)
 * @param matched  판정 근거가 된 이벤트 요약들
 * @param destIp   목적지 IP — network 이벤트 기반 판정
 * @param destPort 목적지 포트 — network 이벤트 기반 판정
 */
public record Alert(
        String host,
        String ruleId,
        String mitre,
        String severity,
        String action,
        long ts,
        List<String> matched,
        String destIp,
        int destPort
) {
}
