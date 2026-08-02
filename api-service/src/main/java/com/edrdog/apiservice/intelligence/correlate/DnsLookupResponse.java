package com.edrdog.apiservice.intelligence.correlate;

/**
 * GET /api/intelligence/dns-lookup 응답. 조회하지 않은 방향은 null 이다.
 * forward/reverse 가 각자 상태를 들고 있어 한쪽이 실패해도 나머지 응답은 그대로 나간다.
 */
public record DnsLookupResponse(CorrelateTarget target, ForwardLookup forward, ReverseLookup reverse) {
}
