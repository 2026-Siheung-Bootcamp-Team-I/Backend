package com.edrdog.apiservice.intelligence.correlate;

/**
 * GET /api/intelligence/dns-lookup 응답. 조회하지 않은 방향은 null 이다.
 *
 * <p>forward/reverse 각각이 자기 상태를 들고 있어서, 한쪽이 실패해도 다른 쪽과 나머지 응답은
 * 그대로 나간다.
 */
public record DnsLookupResponse(CorrelateTarget target, ForwardLookup forward, ReverseLookup reverse) {
}
