package com.edrdog.apiservice.agent;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
import java.util.List;

/**
 * events 요청의 events 배열 각 원소 루트에 tenantId 를 심는 순수 로직.
 *
 * <p>에이전트는 tenantId 를 모른다(node_key 만 안다). 수집 API 가 node_key 로 푼 tenantId 를 여기서
 * 이벤트 루트에 심어 events-raw 로 흘려보내면, collector 가 그 값을 읽어 events 까지 격리 태그를 전파한다.
 *
 * <p>이벤트에 이미 tenantId 가 들어 있어도 신뢰하지 않고 서버가 푼 값으로 덮어쓴다(엔드포인트 위조 방지).
 * 엔드포인트가 보낸 값을 믿으면 다른 조직의 태그를 붙일 수 있다.
 */
public final class EventTagger {

    private EventTagger() {
    }

    /** events 배열의 객체 원소마다 루트 tenantId 를 심어 JSON 문자열 리스트로 반환. 배열이 아니면 빈 리스트. */
    public static List<String> tag(String tenantId, JsonNode events, ObjectMapper mapper) {
        List<String> out = new ArrayList<>();
        if (events == null || !events.isArray()) {
            return out;
        }
        for (JsonNode event : events) {
            if (event == null || !event.isObject()) {
                continue;   // 객체가 아닌 원소는 이벤트가 아님
            }
            ObjectNode tagged = ((ObjectNode) event).put("tenantId", tenantId);
            try {
                out.add(mapper.writeValueAsString(tagged));
            } catch (Exception e) {
                throw new IllegalStateException("이벤트 직렬화 실패", e);
            }
        }
        return out;
    }
}
