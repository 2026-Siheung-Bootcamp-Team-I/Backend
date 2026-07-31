package com.edrdog.apiservice.intelligence.correlate;

import java.util.List;

/**
 * GET /api/intelligence/correlate 응답.
 *
 * <p>liveDns 는 실시간 조회를 껐으면 null 이다. 그래프 엣지에도 실시간 관계가 실려 있지만,
 * 조회가 실패했다는 사실은 엣지로 표현되지 않으므로 여기에 원본 결과를 같이 준다.
 *
 * <p>observedEvents 는 그래프를 만드는 데 쓴 관측 이벤트 수다. 0 이면 그래프에 보이는 것은
 * 실시간 조회 결과뿐이라는 뜻이라, 화면이 "관측된 적 없음"을 말할 수 있어야 한다.
 */
public record CorrelateResponse(
        CorrelateTarget target,
        int observedEvents,
        List<CorrelationNode> nodes,
        List<CorrelationEdge> edges,
        DnsLookupResponse liveDns
) {
}
