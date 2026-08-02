package com.edrdog.apiservice.host;

/** collector 에 등록된 노드의 host/마지막 접속 시각/OS(HostAggregator 입력용 순수 값 객체). */
public record EnrolledHost(String host, long agentSeen, String platform) {
}
