package com.edrdog.apiservice.host.web;

/**
 * 엔드포인트(호스트) 목록 한 행. status 는 영문 enum(healthy|warning|critical),
 * threats 는 열린 alert 총수, lastSeen 은 events 최신 ts(epoch millis).
 * enrolled 는 agent_nodes 에 등록된 기기인지, agentSeen 은 에이전트가 서버에 마지막으로
 * 붙은 시각(epoch millis, 미등록이면 0)이다. 이벤트가 0건이어도 등록만 됐으면 화면에 보이게 하기 위함이다.
 * platform 은 에이전트가 보낸 OS(darwin|windows, 미등록이면 빈 문자열)다.
 */
public record HostResponse(
        String host,
        long lastSeen,
        String status,
        long threats,
        boolean enrolled,
        long agentSeen,
        String platform
) {
}
