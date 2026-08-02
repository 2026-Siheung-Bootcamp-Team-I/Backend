package com.edrdog.apiservice.intelligence.correlate;

/**
 * 그래프 꼭짓점의 종류.
 * PTR_NAME 을 DOMAIN 으로 합치면 조사하는 사람이 PTR 이 답한 이름을 그 IP 의 정체로 읽게 된다.
 */
public enum NodeKind {
    DOMAIN,
    IP,
    HOST,
    PROCESS,
    /** PTR 이 답한 이름. 후보일 뿐이고 IP 를 대체하지 않는다. */
    PTR_NAME
}
