package com.edrdog.apiservice.event;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.List;

/**
 * events.detail(타입별 부가정보 JSON 문자열 한 칸)을 named 필드로 편 것.
 * 에이전트가 관측 못 한 값은 키 자체를 빼므로 없는 키는 null 로 남긴다. 0/빈 값으로 채우면 실제 관측값과 구분이 사라진다.
 * ignoreUnknown 을 빼면 detail 에 새 키가 하나 늘 때마다 파싱이 깨진다.
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

    /** detail 문자열을 파싱한다. 깨진 JSON 에 예외를 던지면 부가정보 하나 때문에 이벤트 전체를 잃는다. */
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
