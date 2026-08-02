package com.edrdog.apiservice.intelligence.correlate;

/**
 * 실시간 DNS 조회. 외부 네트워크를 타는 유일한 부분이라 인터페이스로 갈라 둔다.
 * 구현은 절대 예외를 던지지 않는다. 던지면 DNS 조회 하나 때문에 멀쩡한 관측 데이터까지 화면에 안 뜬다.
 */
public interface DnsResolver {

    /** 도메인 -> IP. A/AAAA 를 모두 본다. */
    ForwardLookup forward(String domain);

    /** IP -> PTR 이름. 결과는 후보일 뿐이고 그 IP 의 정체를 증명하지 않는다. */
    ReverseLookup reverse(String ip);
}
