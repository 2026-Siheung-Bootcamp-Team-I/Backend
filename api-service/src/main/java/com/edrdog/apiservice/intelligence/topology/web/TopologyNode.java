package com.edrdog.apiservice.intelligence.topology.web;

/**
 * 토폴로지 그래프 노드. kind 에 따라 채워지는 칸이 다르고, 해당 없는 칸은 null 이다
 * (0 이나 빈 문자열로 채우면 "관측했는데 0" 과 "해당 없음" 이 구분되지 않는다).
 *
 * @param id        dedup 키 겸 식별자 ({@code host:<host>}, {@code dest:<도메인|IP>}, {@code group:<등록가능도메인>})
 * @param kind      endpoint | destination | domainGroup
 * @param label     화면 표시명
 * @param destKind  destination 일 때 domain | ip (도메인으로 관측되지 않은 목적지는 IP 그대로 둔다)
 * @param group     destination 이 속한 domainGroup 노드 id. 묶이지 않으면 null
 * @param riskScore endpoint 의 위험 점수(0..100)
 * @param openAlerts endpoint 의 기간 내 열린 alert 수(점수의 근거)
 * @param members   domainGroup 에 묶인 목적지 수
 */
public record TopologyNode(String id, String kind, String label, String destKind, String group,
                           Integer riskScore, Long openAlerts, Integer members) {

    public static TopologyNode endpoint(String host, int riskScore, long openAlerts) {
        return new TopologyNode("host:" + host, "endpoint", host, null, null, riskScore, openAlerts, null);
    }

    public static TopologyNode destination(String dest, String destKind, String groupId) {
        return new TopologyNode("dest:" + dest, "destination", dest, destKind, groupId, null, null, null);
    }

    public static TopologyNode domainGroup(String registrableDomain, int members) {
        return new TopologyNode("group:" + registrableDomain, "domainGroup", registrableDomain,
                null, null, null, null, members);
    }
}
