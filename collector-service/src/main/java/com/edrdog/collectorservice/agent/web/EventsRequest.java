package com.edrdog.collectorservice.agent.web;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * 이벤트 전송 요청. events 는 detector 가 판정 입력으로 쓰는 스키마 그대로의 평평한 객체 배열이다.
 * 여기서 형태를 강제하면(DTO 로 바꾸면) 스키마가 늘 때마다 서버를 다시 배포해야 한다.
 */
public record EventsRequest(JsonNode events) {
}
