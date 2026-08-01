package com.edrdog.apiservice.host.web;

/**
 * 엔드포인트(호스트) 목록 한 행. status 는 영문 enum(healthy|warning|critical)이고 riskScore 에서 유도한다(HostStatus).
 * threats 는 열린 alert 총수, lastSeen 은 events 최신 ts(epoch millis).
 * riskScore 는 열린 alert 를 severity 로 가중합한 0..100 값(RiskScore)으로, 토폴로지 엔드포인트 노드와 같은 값이다.
 * 열린 알림이 없으면 0 이다(이건 관측 결과라서 null 이 아니다). 목록에 위험도를 보이려고
 * 토폴로지를 통째로 부르지 않게 하려는 것이다.
 * enrolled 는 agent_nodes 에 등록된 기기인지, agentSeen 은 에이전트가 서버에 마지막으로
 * 붙은 시각(epoch millis, 미등록이면 0)이다. 이벤트가 0건이어도 등록만 됐으면 화면에 보이게 하기 위함이다.
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
