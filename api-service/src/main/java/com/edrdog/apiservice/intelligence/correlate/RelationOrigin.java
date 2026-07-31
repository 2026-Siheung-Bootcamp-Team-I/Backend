package com.edrdog.apiservice.intelligence.correlate;

/**
 * 관계가 어디서 나왔는지. 이 API 의 핵심이라 모든 엣지가 반드시 하나를 달고 나간다.
 *
 * <p>셋을 섞으면 조사하는 사람이 잘못된 결론을 낸다. "우리가 실제로 본 것"과 "지금 밖에
 * 물어본 것"과 "우리가 이어 붙여 추측한 것"은 신뢰도가 전혀 다르기 때문이다.
 */
public enum RelationOrigin {
    /** 우리가 수집한 이벤트에 그대로 들어 있던 사실. */
    OBSERVED,
    /** 관측 두 건을 시간·IP 로 이어 붙여 얻은 추측. 관측이 아니다. */
    INFERRED,
    /** 지금 DNS 서버에 물어본 결과. 우리 이벤트와 무관하며 조회 시점의 상태일 뿐이다. */
    LIVE_DNS
}
