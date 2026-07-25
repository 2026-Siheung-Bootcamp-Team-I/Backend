package com.edrdog.apiservice.osquery;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * osquery log 요청의 data 배열 각 result-log 레코드에 tenantId 를 루트 태깅하는 순수 로직 검증.
 * osquery 원본 로그에는 tenant 정보가 없으므로, node_key 로 푼 tenantId 를 여기서 껍데기 필드로 심는다.
 * collector RawEventMapper 가 이 루트 tenantId 를 읽어 events 까지 전파한다.
 */
class RawLogTaggerTest {

    private final ObjectMapper mapper = new ObjectMapper();

    private JsonNode data(String json) throws Exception {
        return mapper.readTree(json);
    }

    @Test
    void 각_레코드_루트에_tenantId_를_심고_JSON_문자열로_돌려준다() throws Exception {
        JsonNode data = data("""
                [
                  {"name":"process_events","hostIdentifier":"mac-001","columns":{"path":"/bin/bash"}},
                  {"name":"socket_events","hostIdentifier":"mac-001","columns":{"remote_address":"1.2.3.4"}}
                ]
                """);

        List<String> tagged = RawLogTagger.tag("7", data, mapper);

        assertEquals(2, tagged.size());
        for (String rec : tagged) {
            JsonNode node = mapper.readTree(rec);
            assertEquals("7", node.get("tenantId").asText());
        }
        // 원본 필드는 보존
        assertEquals("mac-001", mapper.readTree(tagged.get(0)).get("hostIdentifier").asText());
    }

    @Test
    void data_가_배열이_아니면_빈_리스트() throws Exception {
        assertTrue(RawLogTagger.tag("7", data("{\"node_key\":\"x\"}"), mapper).isEmpty());
        assertTrue(RawLogTagger.tag("7", null, mapper).isEmpty());
    }

    @Test
    void 객체가_아닌_원소는_건너뛴다() throws Exception {
        JsonNode data = data("""
                [ {"name":"process_events","columns":{}}, "쓰레기", 123 ]
                """);

        List<String> tagged = RawLogTagger.tag("7", data, mapper);

        assertEquals(1, tagged.size());
    }

    @Test
    void 이미_들어있는_tenantId_는_신뢰하지_않고_덮어쓴다() throws Exception {
        JsonNode data = data("""
                [ {"name":"process_events","tenantId":"999","columns":{}} ]
                """);

        List<String> tagged = RawLogTagger.tag("7", data, mapper);

        assertEquals("7", mapper.readTree(tagged.get(0)).get("tenantId").asText());
    }
}
