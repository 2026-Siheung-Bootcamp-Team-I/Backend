package com.edrdog.apiservice.agent.web;

/** 이벤트 수신 응답. 에이전트는 이 건수를 확인하고 버퍼에서 그 배치를 지운다. */
public record EventsResponse(int accepted) {
}
