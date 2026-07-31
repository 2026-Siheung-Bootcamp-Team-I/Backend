package com.edrdog.apiservice.intelligence.correlate;

/** 두 꼭짓점을 잇는 관계의 종류. */
public enum RelationType {
    /** 도메인 -> IP. DNS 응답의 A/AAAA 답, 또는 실시간 정방향 조회 결과. */
    RESOLVED_TO,
    /** 도메인 -> 도메인. DNS 응답에 IP 가 아닌 별칭(CNAME)이 실려 온 경우. */
    ALIAS_OF,
    /** 도메인 -> IP. 그 도메인에 붙을 때 실제로 쓴 목적지 IP(network/l7 이벤트). */
    CONNECTED_VIA,
    /** 호스트/프로세스 -> 도메인. DNS 질의를 했다. */
    QUERIED,
    /** 호스트/프로세스 -> 도메인 또는 IP. 실제로 접속했다. */
    CONNECTED,
    /** IP -> PTR 이름. 역방향 조회가 답한 후보 이름이다. */
    PTR_CANDIDATE
}
