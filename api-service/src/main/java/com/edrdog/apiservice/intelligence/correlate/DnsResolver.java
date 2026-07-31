package com.edrdog.apiservice.intelligence.correlate;

/**
 * 실시간 DNS 조회. 외부 네트워크를 타는 유일한 부분이라 인터페이스로 갈라 둔다
 * (조립·매칭 로직은 이것 없이 테스트할 수 있어야 한다).
 *
 * <p>구현은 절대 예외를 던지지 않는다. 실패는 LookupStatus.FAILED 로 돌려준다. 관측 데이터는
 * 멀쩡한데 DNS 조회 하나 때문에 화면 전체가 안 뜨는 일이 없어야 한다.
 */
public interface DnsResolver {

    /** 도메인 -> IP. A/AAAA 를 모두 본다. */
    ForwardLookup forward(String domain);

    /** IP -> PTR 이름. 결과는 후보일 뿐이고 그 IP 의 정체를 증명하지 않는다. */
    ReverseLookup reverse(String ip);
}
