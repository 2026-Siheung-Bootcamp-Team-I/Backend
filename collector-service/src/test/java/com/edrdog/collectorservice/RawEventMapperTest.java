package com.edrdog.collectorservice;

import com.edrdog.collectorservice.dto.Event;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 에이전트가 보낸 평평한 이벤트 JSON → Event 검증 규칙 확인.
 * 이제 columns 껍데기 벗기기나 타입 추측 같은 변환은 하지 않는다. 필수값이 갖춰졌는지만 본다.
 */
class RawEventMapperTest {

    private final ObjectMapper mapper = new ObjectMapper();

    private Optional<Event> map(String raw) {
        return RawEventMapper.map(raw, mapper);
    }

    @Test
    void process_이벤트를_그대로_통과시킨다() {
        String raw = """
                {
                  "host": "lab-mac",
                  "type": "process",
                  "ts": 1785341400000,
                  "process": "sh",
                  "parent": "bash",
                  "cmdline": "sh -c whoami",
                  "tenantId": "1"
                }
                """;

        Event e = map(raw).orElseThrow();

        assertEquals("lab-mac", e.host());
        assertEquals(Event.TYPE_PROCESS, e.type());
        assertEquals(1785341400000L, e.ts());
        assertEquals("sh", e.process());
        assertEquals("bash", e.parent());
        assertEquals("sh -c whoami", e.cmdline());
        assertEquals("1", e.tenantId());
    }

    @Test
    void network_이벤트를_그대로_통과시킨다() {
        String raw = """
                {
                  "host": "lab-mac",
                  "type": "network",
                  "ts": 1785341400000,
                  "process": "curl",
                  "destIp": "203.0.113.9",
                  "destPort": 443
                }
                """;

        Event e = map(raw).orElseThrow();

        assertEquals(Event.TYPE_NETWORK, e.type());
        assertEquals("curl", e.process());
        assertEquals("203.0.113.9", e.destIp());
        assertEquals(443, e.destPort());
    }

    @Test
    void file_이벤트를_그대로_통과시킨다() {
        String raw = """
                {
                  "host": "lab-mac",
                  "type": "file",
                  "ts": 1785341400000,
                  "process": "com.evil.plist",
                  "cmdline": "/Users/victim/Library/LaunchAgents/com.evil.plist"
                }
                """;

        Event e = map(raw).orElseThrow();

        assertEquals(Event.TYPE_FILE, e.type());
        assertEquals("com.evil.plist", e.process());
        assertEquals("/Users/victim/Library/LaunchAgents/com.evil.plist", e.cmdline());
    }

    @Test
    void script_이벤트를_그대로_통과시킨다() {
        String raw = """
                {
                  "host": "win-001",
                  "type": "script",
                  "ts": 1785341400000,
                  "process": "powershell.exe",
                  "parent": "explorer.exe",
                  "cmdline": "powershell -File C:\\\\Users\\\\victim\\\\Downloads\\\\a.ps1"
                }
                """;

        Event e = map(raw).orElseThrow();

        assertEquals(Event.TYPE_SCRIPT, e.type());
        assertEquals("powershell.exe", e.process());
        assertEquals("explorer.exe", e.parent());
        assertEquals("powershell -File C:\\Users\\victim\\Downloads\\a.ps1", e.cmdline());
    }

    @Test
    void tenantId_가_없으면_null_로_흐른다() {
        String raw = """
                {
                  "host": "lab-mac",
                  "type": "process",
                  "ts": 1785341400000,
                  "process": "sh"
                }
                """;

        assertNull(map(raw).orElseThrow().tenantId());
    }

    @Test
    void 깨진_JSON_은_예외없이_스킵한다() {
        assertTrue(map("{not-json").isEmpty());
        assertTrue(map("").isEmpty());
    }

    @Test
    void 객체가_아니면_스킵한다() {
        assertTrue(map("[1, 2, 3]").isEmpty());
    }

    @Test
    void host_가_없으면_스킵한다() {
        String raw = """
                { "type": "process", "ts": 1785341400000, "process": "sh" }
                """;

        assertTrue(map(raw).isEmpty());
    }

    @Test
    void host_가_빈문자열이면_스킵한다() {
        String raw = """
                { "host": "", "type": "process", "ts": 1785341400000 }
                """;

        assertTrue(map(raw).isEmpty());
    }

    @Test
    void 알수없는_type_은_스킵한다() {
        String raw = """
                { "host": "lab-mac", "type": "registry", "ts": 1785341400000 }
                """;

        assertTrue(map(raw).isEmpty());
    }

    @Test
    void ts_가_없으면_스킵한다() {
        String raw = """
                { "host": "lab-mac", "type": "process" }
                """;

        assertTrue(map(raw).isEmpty());
    }

    @Test
    void ts_가_0이하면_스킵한다() {
        String raw = """
                { "host": "lab-mac", "type": "process", "ts": 0 }
                """;

        assertTrue(map(raw).isEmpty());
    }

    @Test
    void ts_가_초_단위로_보이면_스킵한다() {
        // 1700000000 은 epoch seconds 로는 그럴듯하지만 millis 로 보면 1970년 근방이라 잘못된 값이다.
        String raw = """
                { "host": "lab-mac", "type": "process", "ts": 1700000000 }
                """;

        assertTrue(map(raw).isEmpty());
    }

    @Test
    void network_인데_destIp_가_없으면_스킵한다() {
        String raw = """
                { "host": "lab-mac", "type": "network", "ts": 1785341400000, "process": "curl" }
                """;

        assertTrue(map(raw).isEmpty());
    }

    @Test
    void network_인데_destIp_가_빈문자열이면_스킵한다() {
        String raw = """
                { "host": "lab-mac", "type": "network", "ts": 1785341400000, "destIp": "" }
                """;

        assertTrue(map(raw).isEmpty());
    }
}
