package com.edrdog.apiservice.intelligence.correlate;

/** 상관분석/DNS 조회의 입력이 무엇인지. 도메인이냐 IP 냐에 따라 조회 방향이 갈린다. */
public enum TargetKind {
    DOMAIN,
    IP
}
