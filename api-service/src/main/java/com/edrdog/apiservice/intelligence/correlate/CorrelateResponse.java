package com.edrdog.apiservice.intelligence.correlate;

import java.util.List;

/**
 * GET /api/intelligence/correlate 응답. liveDns 는 실시간 조회를 껐으면 null 이다.
 * 조회 실패는 엣지로 표현되지 않으므로 liveDns 에 원본 결과를 같이 준다.
 * observedEvents 가 0 이면 그래프에 보이는 것이 실시간 조회 결과뿐이라는 뜻이다.
 */
public record CorrelateResponse(
        CorrelateTarget target,
        int observedEvents,
        List<CorrelationNode> nodes,
        List<CorrelationEdge> edges,
        DnsLookupResponse liveDns
) {
}
