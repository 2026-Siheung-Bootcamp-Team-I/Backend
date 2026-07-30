package com.edrdog.apiservice.host;

/**
 * agent_nodes 에 등록된 노드의 host/마지막 접속 시각(HostAggregator 입력용 순수 값 객체).
 * JPA 엔티티(AgentNode)를 그대로 아래로 넘기지 않고 HostService 에서 변환해 넘긴다
 * (HostAlertCount 가 AlertStatusRecord 를 그대로 안 쓰는 것과 같은 패턴).
 */
public record EnrolledHost(String host, long agentSeen) {
}
