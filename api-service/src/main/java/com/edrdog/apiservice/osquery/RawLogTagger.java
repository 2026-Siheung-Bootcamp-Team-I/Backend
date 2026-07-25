package com.edrdog.apiservice.osquery;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
import java.util.List;

/**
 * osquery log 요청의 data 배열 각 result-log 레코드에 tenantId 를 루트로 태깅하는 순수 로직.
 *
 * <p>osquery 원본 로그에는 tenant 정보가 없다(엔드포인트는 node_key 만 안다). 수집 API 가 node_key 로
 * 푼 tenantId 를 여기서 레코드 루트에 심어 events-raw 로 흘려보내면, collector 의 RawEventMapper 가
 * 루트 {@code tenantId} 를 읽어 events 까지 격리 태그를 전파한다.
 *
 * <p>레코드에 이미 tenantId 가 들어 있어도 신뢰하지 않고 서버가 푼 값으로 덮어쓴다(엔드포인트 위조 방지).
 */
public final class RawLogTagger {

    private RawLogTagger() {
    }

    /** data 배열의 객체 원소마다 루트 tenantId 를 심어 JSON 문자열 리스트로 반환. 배열이 아니면 빈 리스트. */
    public static List<String> tag(String tenantId, JsonNode data, ObjectMapper mapper) {
        List<String> out = new ArrayList<>();
        if (data == null || !data.isArray()) {
            return out;
        }
        for (JsonNode record : data) {
            if (record == null || !record.isObject()) {
                continue;   // 객체가 아닌 원소는 result-log 가 아님
            }
            ObjectNode tagged = ((ObjectNode) record).put("tenantId", tenantId);
            try {
                out.add(mapper.writeValueAsString(tagged));
            } catch (Exception e) {
                throw new IllegalStateException("result-log 직렬화 실패", e);
            }
        }
        return out;
    }
}
