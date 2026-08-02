package com.edrdog.collectorservice.agent.web;

/** 이벤트 수신 응답. events 로 발행된 건수다(검증에서 걸린 건은 빠진다). */
public record EventsResponse(int accepted) {
}
