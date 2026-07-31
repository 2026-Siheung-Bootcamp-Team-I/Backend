package com.edrdog.apiservice.intelligence.topology.web;

import java.util.List;

/**
 * 엔드포인트 → 목적지 관계 하나.
 *
 * @param events    기간 내 이벤트 수
 * @param alerts    기간 내 알림 수. 0 이면 알림 없이 관측만 된 관계다(프론트가 점선으로 그린다)
 * @param protocols 관측된 프로토콜 라벨(tcp/udp/tls/http...). 관측 못 했으면 빈 목록이다
 * @param lastSeen  마지막 관측 시각(epoch millis)
 */
public record TopologyEdge(String from, String to, long events, long alerts, List<String> protocols,
                           long lastSeen) {
}
