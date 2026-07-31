package com.edrdog.apiservice.intelligence.correlate;

/**
 * 그래프 꼭짓점의 종류.
 *
 * <p>PTR_NAME 을 DOMAIN 과 따로 두는 이유: PTR 은 IP 소유자가 아무 이름이나 적어 둘 수 있어
 * 검증된 이름이 아니다. 같은 DOMAIN 으로 합치면 화면에서 "우리가 관측한 도메인"과 구분이
 * 사라지고, 조사하는 사람이 PTR 이 답한 이름을 그 IP 의 정체로 읽게 된다.
 */
public enum NodeKind {
    DOMAIN,
    IP,
    HOST,
    PROCESS,
    /** PTR 이 답한 이름. 후보일 뿐이고 IP 를 대체하지 않는다. */
    PTR_NAME
}
