package com.edrdog.apiservice.search.web;

import com.edrdog.apiservice.host.web.HostResponse;

/**
 * GET /api/search 응답. 화면이 섹션으로 그리므로 종류별로 나눠 준다.
 * from/to 를 안 돌려주면 화면이 "없다" 와 "이 기간에는 없다" 를 구분해 보여 줄 수 없다.
 *
 * @param query 실제로 적용된 질의어(앞뒤 공백을 뗀 값)
 * @param from  적용된 시간 하한 (epoch millis)
 * @param to    적용된 시간 상한 (epoch millis)
 * @param hosts 호스트 이름이 걸린 엔드포인트. 목록 조회(GET /api/hosts)와 같은 모양이라 화면이 같은 줄을 재사용한다
 */
public record SearchResponse(
        String query,
        long from,
        long to,
        SearchSection<HostResponse> hosts,
        SearchSection<AlertHit> alerts,
        SearchSection<EventHit> events
) {
}
