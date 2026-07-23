package com.edrdog.apiservice.osquery;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * config 엔드포인트가 내려줄 수집 스케줄이 플랫폼별로 갈리고, parent 를 이름으로 채우는지 검증.
 * 결과-log 의 {@code name}(스케줄 키)은 collector 의 RawEventMapper type 판정과 맞물리므로 키 이름도 고정한다.
 */
class OsqueryConfigTest {

    private final ObjectMapper mapper = new ObjectMapper();

    private JsonNode schedule(String platform) throws Exception {
        return mapper.readTree(OsqueryConfig.forPlatform(platform)).get("schedule");
    }

    @Test
    void macOS_는_es_process_events_와_socket_events_를_내려준다() throws Exception {
        JsonNode s = schedule("darwin");

        assertTrue(s.has("process_events"), "mac 프로세스 스케줄 키는 process_events (mapper=process)");
        assertTrue(s.has("socket_events"), "mac 네트워크 스케줄 키는 socket_events (mapper=network)");

        String procQuery = s.get("process_events").get("query").asText();
        assertTrue(procQuery.contains("es_process_events"), "EndpointSecurity 테이블을 써야 한다");
        assertTrue(procQuery.contains("processes"), "parent 이름을 위해 processes 조인이 있어야 한다");
        assertTrue(procQuery.contains("AS parent"), "parent 컬럼을 이름으로 별칭해야 RawEventMapper 가 읽는다");

        assertTrue(s.has("script_events"), "mac 스크립트 스케줄 키는 script_events (mapper=script)");
        assertTrue(s.has("file_events"), "mac 파일 스케줄 키는 file_events (mapper=file)");
        assertTrue(s.get("file_events").get("query").asText().contains("target_path"),
                "file_events 는 판정용 target_path 를 내려야 한다");
    }

    @Test
    void macOS_는_자동실행_FIM_감시_경로를_내려준다() throws Exception {
        JsonNode root = mapper.readTree(OsqueryConfig.forPlatform("darwin"));

        JsonNode autorun = root.get("file_paths").get("autorun");
        assertTrue(autorun.isArray() && autorun.size() > 0, "file_events FIM 대상 경로가 있어야 한다");
        assertTrue(autorun.toString().contains("LaunchAgents"), "LaunchAgents 자동실행 경로를 감시해야 한다");
    }

    @Test
    void windows_는_process_etw_events_만_내려준다() throws Exception {
        JsonNode s = schedule("windows");

        assertTrue(s.has("process_etw_events"), "win 프로세스 스케줄 키는 process_etw_events");
        assertFalse(s.has("socket_events"), "win 은 core osquery 실시간 소켓 테이블이 없다(Zeek 담당)");

        String procQuery = s.get("process_etw_events").get("query").asText();
        assertTrue(procQuery.contains("process_etw_events"), "ETW 테이블을 써야 한다");
        assertTrue(procQuery.contains("processes"), "parent 이름을 위해 processes 조인(ppid)이 있어야 한다");
        assertTrue(procQuery.contains("AS parent"), "parent 를 이름으로 별칭해야 한다");

        assertTrue(s.has("script_etw_events"), "win 스크립트 스케줄 키는 script_etw_events (mapper=script)");
        assertTrue(s.has("file_events"), "win 파일 스케줄 키는 file_events (mapper=file)");
    }

    @Test
    void 미상_플랫폼은_macOS_스케줄로_폴백한다() throws Exception {
        JsonNode s = schedule(null);

        assertTrue(s.has("process_events"), "플랫폼 미상이면 mac 스케줄로 폴백");
        assertTrue(s.has("socket_events"));
    }
}
