package com.edrdog.apiservice.agent.web;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * 이벤트 전송 요청. events 는 detector 가 판정 입력으로 쓰는 스키마 그대로의 평평한 객체 배열이다.
 * 서버는 형태를 강제하지 않고(스키마가 늘어도 서버 재배포가 필요 없다) tenantId 만 심어 흘려보낸다.
 */
public record EventsRequest(JsonNode events) {
}
