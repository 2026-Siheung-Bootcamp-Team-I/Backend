package com.edrdog.apiservice.intelligence.correlate;

import java.util.List;

/** 정방향(도메인 -> IP) 실시간 조회 결과. 실패해도 예외 대신 이 값으로 담아 200 으로 나간다. */
public record ForwardLookup(LookupStatus status, List<String> addresses, String error) {

    public static ForwardLookup ok(List<String> addresses) {
        return new ForwardLookup(LookupStatus.OK, addresses, null);
    }

    public static ForwardLookup notFound() {
        return new ForwardLookup(LookupStatus.NOT_FOUND, List.of(), null);
    }

    public static ForwardLookup failed(String error) {
        return new ForwardLookup(LookupStatus.FAILED, List.of(), error);
    }
}
