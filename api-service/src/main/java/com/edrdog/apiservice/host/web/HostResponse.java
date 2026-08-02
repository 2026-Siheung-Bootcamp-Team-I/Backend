package com.edrdog.apiservice.host.web;

/**
 * 엔드포인트(호스트) 목록 한 행. status 는 영문 enum(healthy|warning|critical)이고 riskScore 에서 유도한다(HostStatus).
 * threats 는 열린 alert 총수, lastSeen 은 events 최신 ts(epoch millis), riskScore 는 열린 alert 를
 * severity 로 가중합한 0..100 값(RiskScore)으로 토폴로지 엔드포인트 노드와 같은 값이다.
 * enrolled 는 agent_nodes 등록 여부, agentSeen 은 에이전트가 마지막으로 붙은 시각(미등록이면 0),
 * platform 은 에이전트가 보낸 OS(darwin|windows, 미등록이면 빈 문자열)다.
 */
public record HostResponse(
        String host,
        long lastSeen,
        String status,
        long threats,
        int riskScore,
        boolean enrolled,
        long agentSeen,
        String platform
) {
}
