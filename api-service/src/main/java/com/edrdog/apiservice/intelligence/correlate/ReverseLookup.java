package com.edrdog.apiservice.intelligence.correlate;

import java.util.List;

/**
 * 역방향(IP -> PTR 이름) 실시간 조회 결과.
 * 필드가 hostname 이 아니라 ptrNames 인 이유는 PTR 이 그 IP 의 정체를 증명하지 않기 때문이다. IP 를 대체하지 않는다.
 */
public record ReverseLookup(LookupStatus status, List<String> ptrNames, String error) {

    public static ReverseLookup ok(List<String> ptrNames) {
        return new ReverseLookup(LookupStatus.OK, ptrNames, null);
    }

    public static ReverseLookup notFound() {
        return new ReverseLookup(LookupStatus.NOT_FOUND, List.of(), null);
    }

    public static ReverseLookup failed(String error) {
        return new ReverseLookup(LookupStatus.FAILED, List.of(), error);
    }
}
