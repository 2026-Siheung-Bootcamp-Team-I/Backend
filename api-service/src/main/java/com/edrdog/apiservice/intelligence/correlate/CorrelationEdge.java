package com.edrdog.apiservice.intelligence.correlate;

/**
 * 관계 하나. 같은 (from, to, relation, origin) 은 한 줄로 합치고 몇 번 관측됐는지를 센다.
 *
 * <p>observations/firstSeen/lastSeen 은 관측(OBSERVED)과 추론(INFERRED)에만 의미가 있다.
 * 실시간 조회(LIVE_DNS)는 뒷받침하는 이벤트가 없으므로 0/null 로 둔다. 여기에 1 을 채우면
 * 화면에서 관측 한 건과 구분되지 않는다.
 *
 * <p>basis 는 추론일 때만 채운다. 무엇을 근거로 이었는지 보여야 조사하는 사람이 그 추론을
 * 스스로 검증할 수 있다.
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
