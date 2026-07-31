package com.edrdog.apiservice.intelligence.correlate;

import java.util.List;

/**
 * 역방향(IP -> PTR 이름) 실시간 조회 결과.
 *
 * <p>필드 이름이 hostname 이 아니라 ptrNames 인 이유: PTR 레코드는 IP 를 가진 쪽이 아무 이름이나
 * 적어 둘 수 있어서 그 IP 의 정체를 증명하지 않는다. "이 IP 의 이름"으로 읽히면 안 되고
 * "PTR 이 이렇게 답했다"로 읽혀야 한다. 원본 IP 를 대체하는 값이 아니다.
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
