package com.edrdog.collectorservice;

import com.edrdog.collectorservice.dto.Event;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * osquery 원시 result-log → Event 정규화 규칙 검증.
 * 규칙: columns 껍데기 flatten, unixTime(초)→ts(밀리초), path→basename(프로세스명),
 * name 으로 type 판정(socket/network→network, 그 외→process), removed 액션은 스킵.
 */
class RawEventMapperTest {

    private final ObjectMapper mapper = new ObjectMapper();

    private Optional<Event> map(String raw) {
        return RawEventMapper.map(raw, mapper);
    }

    @Test
    void process_added_이벤트를_정규화한다() {
        String raw = """
                {
                  "name": "process_events",
                  "hostIdentifier": "mac-001",
                  "unixTime": "1700000000",
                  "action": "added",
                  "columns": {
                    "path": "/bin/bash",
                    "cmdline": "bash -c whoami",
                    "parent": "zsh",
                    "pid": "1234"
                  }
                }
                """;

        Event e = map(raw).orElseThrow();

        assertEquals("mac-001", e.host());
        assertEquals(Event.TYPE_PROCESS, e.type());
        assertEquals(1700000000000L, e.ts());       // 초 → 밀리초
        assertEquals("bash", e.process());          // path basename
        assertEquals("zsh", e.parent());
        assertEquals("bash -c whoami", e.cmdline());
    }

    @Test
    void windows_경로도_basename_으로_뽑는다() {
        String raw = """
                {
                  "name": "process_etw_events",
                  "hostIdentifier": "win-001",
                  "unixTime": "1700000000",
                  "action": "added",
                  "columns": {
                    "path": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",
                    "cmdline": "powershell -enc ...",
                    "parent": "WINWORD.EXE"
                  }
                }
                """;

        Event e = map(raw).orElseThrow();

        assertEquals("win-001", e.host());
        assertEquals(Event.TYPE_PROCESS, e.type());
        assertEquals("powershell.exe", e.process());
        assertEquals("WINWORD.EXE", e.parent());
    }

    @Test
    void socket_connect_이벤트를_network_로_정규화한다() {
        String raw = """
                {
                  "name": "socket_events",
                  "hostIdentifier": "mac-001",
                  "unixTime": "1700000005",
                  "action": "added",
                  "columns": {
                    "action": "connect",
                    "path": "/usr/bin/curl",
                    "remote_address": "203.0.113.9",
                    "remote_port": "443",
                    "pid": "1300"
                  }
                }
                """;

        Event e = map(raw).orElseThrow();

        assertEquals(Event.TYPE_NETWORK, e.type());
        assertEquals(1700000005000L, e.ts());
        assertEquals("curl", e.process());
        assertEquals("203.0.113.9", e.destIp());
        assertEquals(443, e.destPort());
    }

    @Test
    void removed_액션은_스킵한다() {
        String raw = """
                {
                  "name": "process_events",
                  "hostIdentifier": "mac-001",
                  "unixTime": "1700000000",
                  "action": "removed",
                  "columns": { "path": "/bin/bash" }
                }
                """;

        assertTrue(map(raw).isEmpty());
    }

    @Test
    void columns_가_없으면_스킵한다() {
        String raw = """
                { "name": "process_events", "hostIdentifier": "mac-001", "unixTime": "1700000000", "action": "added" }
                """;

        assertTrue(map(raw).isEmpty());
    }

    @Test
    void 깨진_JSON_은_예외없이_스킵한다() {
        assertTrue(map("{not-json").isEmpty());
        assertTrue(map("").isEmpty());
    }
}
