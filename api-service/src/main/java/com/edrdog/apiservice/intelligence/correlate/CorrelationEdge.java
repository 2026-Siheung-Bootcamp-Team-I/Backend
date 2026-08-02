package com.edrdog.apiservice.intelligence.correlate;

/**
 * 관계 하나. 같은 (from, to, relation, origin) 은 한 줄로 합치고 몇 번 관측됐는지를 센다.
 * LIVE_DNS 의 observations 에 1 을 채우면 화면에서 관측 한 건과 구분되지 않아 0/null 로 둔다.
 * basis 는 추론일 때만 채운다.
 */
public record CorrelationEdge(
        String from,
        String to,
        RelationType relation,
        RelationOrigin origin,
        int observations,
        Long firstSeen,
        Long lastSeen,
        String basis
) {
}
