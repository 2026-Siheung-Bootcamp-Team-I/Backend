package com.edrdog.collectorservice.agent;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
import java.util.List;

/**
 * events 요청의 events 배열 각 원소 루트에 tenantId 를 심는 순수 로직.
 *
 * <p>에이전트는 tenantId 를 모른다(node_key 만 안다). 수집 API 가 node_key 로 푼 tenantId 를 여기서
 * 이벤트 루트에 심어야 events 를 소비하는 쪽까지 격리 태그가 전파된다.
 *
 * <p>이벤트에 이미 tenantId 가 들어 있어도 신뢰하지 않고 서버가 푼 값으로 덮어쓴다(엔드포인트 위조 방지).
 * 엔드포인트가 보낸 값을 믿으면 다른 조직의 태그를 붙일 수 있다.
 */
public final class EventTagger {

    private EventTagger() {
    }

    public static List<String> tag(String tenantId, JsonNode events, ObjectMapper mapper) {
        List<String> out = new ArrayList<>();
        if (events == null || !events.isArray()) {
            return out;
        }
        for (JsonNode event : events) {
            if (event == null || !event.isObject()) {
                continue;
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
