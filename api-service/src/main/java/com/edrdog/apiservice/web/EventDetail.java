package com.edrdog.apiservice.web;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.List;

/**
 * events.detail(타입별 부가정보 JSON 문자열 한 칸)을 named 필드로 편 것.
 * 에이전트는 관측하지 못한 값을 아예 키에서 뺀다(event.go 의 putInt/putString 주석 참고).
 * 그래서 여기서도 없는 키는 null 로 남기고 0/빈 값으로 채우지 않는다. status 처럼 0 이
 * 유효한 관측값인 필드는 에이전트가 그 값을 실제로 넣으므로 이 규칙만 지키면 저절로 맞는다.
 *
 * ignoreUnknown 인 이유는 detail 에 새 키가 늘어도(예: 인증서 필드) API 를 안 고치고
 * 이 레코드가 계속 동작해야 하기 때문이다. 늘어난 키는 EventResponse 의 원본 detail 문자열로 본다.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record EventDetail(
        Integer pid,
        Integer ppid,
        String protocol,
        String action,
        String queryType,
        List<String> answers,
        Integer status,
        String tlsVersion,
        List<String> alpn,
        String l7Protocol,
        String httpMethod,
        String httpPath,
        String httpUserAgent,
        Integer httpStatusCode
) {
    private static final EventDetail EMPTY = new EventDetail(
            null, null, null, null, null, null, null, null, null, null, null, null, null, null);

    /**
     * detail 문자열을 파싱한다. 비어 있거나 깨진 JSON 이어도 예외를 던지지 않고 빈 값을 준다
     * (에이전트의 encodeDetail 과 같은 선택: 부가정보 하나 때문에 이벤트 전체를 잃지 않는다).
     */
    public static EventDetail parse(String raw, ObjectMapper mapper) {
        if (raw == null || raw.isBlank()) {
            return EMPTY;
        }
        try {
            return mapper.readValue(raw, EventDetail.class);
        } catch (Exception e) {
            return EMPTY;
        }
    }
}
