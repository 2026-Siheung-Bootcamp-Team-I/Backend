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

    /**
     * osquery 가 enroll 에 싣는 platform_type 은 이름이 아니라 비트마스크 숫자다.
     * 실기기에서 Windows 는 2, macOS 는 21 로 들어왔다(POSIX 1 + BSD 4 + OSX 16).
     * 문자열로만 판정하면 Windows 가 macOS 스케줄을 받아 없는 테이블을 조회하고, 수집이 조용히 0건이 된다.
     */
    @Test
    void platform_type_이_숫자로_와도_Windows_를_알아본다() throws Exception {
        JsonNode s = schedule("2");

        assertTrue(s.has("process_etw_events"), "platform_type=2 는 Windows(TYPE_WINDOWS=0x02)");
        assertFalse(s.has("process_events"), "mac 스케줄을 내려주면 없는 테이블을 조회하게 된다");
    }

    @Test
    void platform_type_숫자가_macOS_면_mac_스케줄을_내려준다() throws Exception {
        JsonNode s = schedule("21");

        assertTrue(s.has("process_events"), "platform_type=21 은 macOS(POSIX+BSD+OSX)");
        assertFalse(s.has("process_etw_events"));
    }

    @Test
    void Windows_비트가_없는_숫자는_macOS_로_폴백한다() throws Exception {
        JsonNode s = schedule("9");   // POSIX(1) + LINUX(8)

        assertTrue(s.has("process_events"), "Windows 비트가 없으면 mac 스케줄로 폴백");
    }

    /**
     * file_events 는 macOS/Linux 전용 테이블이다. Windows 에서 그 쿼리를 내려주면
     * "no such table" 로 실패한다(실기기 로그로 확인). NTFS USN 저널은 별도 테이블을 쓴다.
     */
    @Test
    void windows_파일_감시는_ntfs_journal_events_를_쓴다() throws Exception {
        JsonNode s = schedule("windows");

        String query = s.get("file_events").get("query").asText();
        assertTrue(query.contains("ntfs_journal_events"), "Windows 파일 감시는 NTFS USN 저널 테이블");
        assertFalse(query.contains("FROM file_events"), "Windows 에 file_events 테이블은 없다");
        // 백슬래시가 하나여야 실제 Windows 경로와 매칭된다. 이스케이프가 한 겹 남으면
        // 조건이 절대 참이 되지 않아, 오류 없이 결과만 0건이 된다.
        assertTrue(query.contains("%\\Start Menu\\Programs\\Startup\\%"),
                "시작프로그램 경로로 걸러야 한다(백슬래시 1개). 실제 쿼리: " + query);
    }

    @Test
    void windows_파일_이벤트는_path_컬럼을_내려준다() throws Exception {
        JsonNode s = schedule("windows");

        // ntfs_journal_events 의 경로 컬럼은 target_path 가 아니라 path 다(실기기 PRAGMA 로 확인).
        // RawEventMapper 는 target_path 가 없으면 path 로 폴백하므로 별칭 없이 그대로 내려도 된다.
        String query = s.get("file_events").get("query").asText();
        assertTrue(query.contains("path"), "판정에 쓸 경로 컬럼이 있어야 한다");
        assertTrue(query.contains("time"), "이벤트 시각이 있어야 한다");
    }
}
