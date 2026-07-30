package com.edrdog.apiservice.agent;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * events 배열 각 원소 루트에 tenantId 를 심는 순수 로직 검증.
 * 에이전트는 tenant 를 모르므로(node_key 만 안다) 서버가 푼 값을 여기서 심는다.
 * collector 가 이 루트 tenantId 를 읽어 events 까지 전파한다.
 */
class EventTaggerTest {

    private final ObjectMapper mapper = new ObjectMapper();

    private JsonNode events(String json) throws Exception {
        return mapper.readTree(json);
    }

    @Test
    void 각_이벤트_루트에_tenantId_를_심고_JSON_문자열로_돌려준다() throws Exception {
        JsonNode events = events("""
                [
                  {"host":"lab-mac","type":"process","ts":1785341400000,"process":"sh","parent":"bash"},
                  {"host":"lab-mac","type":"network","ts":1785341400000,"destIp":"1.2.3.4","destPort":443}
                ]
                """);

        List<String> tagged = EventTagger.tag("7", events, mapper);

        assertEquals(2, tagged.size());
        for (String rec : tagged) {
            assertEquals("7", mapper.readTree(rec).get("tenantId").asText());
        }
        // 원본 필드는 보존
        assertEquals("lab-mac", mapper.readTree(tagged.get(0)).get("host").asText());
        assertEquals("sh", mapper.readTree(tagged.get(0)).get("process").asText());
    }

    @Test
    void events_가_배열이_아니면_빈_리스트() throws Exception {
        assertTrue(EventTagger.tag("7", events("{\"host\":\"lab-mac\"}"), mapper).isEmpty());
        assertTrue(EventTagger.tag("7", null, mapper).isEmpty());
    }

    @Test
    void 객체가_아닌_원소는_건너뛴다() throws Exception {
        JsonNode events = events("""
                [ {"host":"lab-mac","type":"process"}, "쓰레기", 123 ]
                """);

        assertEquals(1, EventTagger.tag("7", events, mapper).size());
    }

    /**
     * 엔드포인트가 보낸 tenantId 를 믿으면 다른 조직의 태그를 붙일 수 있다.
     * 서버가 node_key 로 푼 값으로 무조건 덮어쓴다.
     */
    @Test
    void 이미_들어있는_tenantId_는_신뢰하지_않고_덮어쓴다() throws Exception {
        JsonNode events = events("""
                [ {"host":"lab-mac","type":"process","tenantId":"999"} ]
                """);

        List<String> tagged = EventTagger.tag("7", events, mapper);

        assertEquals("7", mapper.readTree(tagged.get(0)).get("tenantId").asText());
    }
}
