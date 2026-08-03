package com.edrdog.apiservice.alert;

import com.edrdog.apiservice.alert.web.SourceEvent;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * 판정을 유발한 원본 이벤트를 events 행에서 고르는 순수 로직 검증.
 *
 * <p>핵심은 시각이 1차 기준이 아니라는 것이다. 실기기는 초당 십여 건씩 이벤트를 내므로 좁은 창 안에도
 * 수백 건이 들어오고, 그중 시각이 가장 가까운 것을 고르는 건 제비뽑기다. 조사 화면에서 틀린 원인을
 * 확신에 차서 보여 주는 건 아무것도 안 보여 주는 것보다 나쁘다. 그래서 알림이 들고 있는 판별자
 * (근거 요약 / 목적지 / 룰)로 후보를 먼저 좁히고, 그 안에서만 시각을 쓴다.
 */
class SourceEventMatcherTest {

    private static Map<String, Object> event(long ts, String type, String process, String parent) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("host", "h1");
        row.put("type", type);
        row.put("ts", String.valueOf(ts));
        row.put("process", process);
        row.put("parent", parent);
        row.put("cmdline", "");
        row.put("dest_ip", "");
        row.put("dest_port", 0);
        row.put("domain", "");
        row.put("detail", "");
        row.put("sha256", "");
        return row;
    }

    private static Map<String, Object> networkEvent(long ts, String destIp, int destPort) {
        Map<String, Object> row = event(ts, "network", "chrome.exe", "");
        row.put("dest_ip", destIp);
        row.put("dest_port", destPort);
        return row;
    }

    /** 판정기록 한 행. matched 마지막 줄이 판정을 완성시킨(= alert.ts 인) 이벤트의 요약이다. */
    private static Map<String, Object> alert(long ts, String ruleId, List<String> matched) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("ts", String.valueOf(ts));
        row.put("rule_id", ruleId);
        row.put("matched", matched);
        row.put("domain", "");
        row.put("dest_ip", "");
        return row;
    }

    @Test
    void 시각이_더_가까운_무관한_이벤트가_있어도_근거요약과_맞는_쪽을_고른다() {
        Map<String, Object> a = alert(1000, "SUSPICIOUS_PROCESS_CHAIN",
                List.of("process winword.exe (parent explorer.exe)", "process powershell.exe (parent winword.exe)"));

        SourceEvent e = SourceEventMatcher.match(List.of(
                event(1001, "process", "noise.exe", "bash"),      // 더 가깝지만 무관
                event(1200, "process", "powershell.exe", "winword.exe")), a);

        assertEquals("powershell.exe", e.process());
        assertEquals(SourceEvent.BY_SUMMARY, e.matchedBy());
    }

    @Test
    void 같은_이름이어도_부모가_다르면_후보가_아니다() {
        Map<String, Object> a = alert(1000, "SUSPICIOUS_PROCESS_CHAIN",
                List.of("process powershell.exe (parent winword.exe)"));

        SourceEvent e = SourceEventMatcher.match(List.of(
                event(1001, "process", "powershell.exe", "explorer.exe"),   // 더 가깝지만 부모가 다르다
                event(1300, "process", "powershell.exe", "winword.exe")), a);

        assertEquals(1300L, e.ts());
    }

    @Test
    void 근거요약이_network_면_목적지가_일치하는_쪽을_고른다() {
        Map<String, Object> a = alert(1000, "DOWNLOAD_AND_EXECUTE", List.of("network 203.0.113.9:443"));

        SourceEvent e = SourceEventMatcher.match(List.of(
                networkEvent(1001, "10.0.0.1", 443),      // 더 가깝지만 다른 목적지
                networkEvent(1300, "203.0.113.9", 443)), a);

        assertEquals("203.0.113.9", e.destIp());
        assertEquals(SourceEvent.BY_SUMMARY, e.matchedBy());
    }

    @Test
    void 판별자가_있는데_일치하는_후보가_없으면_null_이고_시각으로_되돌아가지_않는다() {
        Map<String, Object> a = alert(1000, "SUSPICIOUS_PROCESS_CHAIN",
                List.of("process powershell.exe (parent winword.exe)"));

        assertNull(SourceEventMatcher.match(List.of(
                event(1000, "process", "noise.exe", "bash"),
                event(1001, "file", "x", "")), a));
    }

    @Test
    void 근거요약이_없으면_rule_id_로_이벤트_type_을_좁힌다() {
        Map<String, Object> a = alert(1000, "SCRIPT_FROM_TEMP_PATH", List.of());

        SourceEvent e = SourceEventMatcher.match(List.of(
                event(1001, "process", "noise.exe", "bash"),      // 더 가깝지만 type 이 다르다
                event(1300, "script", "setup.ps1", "explorer.exe")), a);

        assertEquals("setup.ps1", e.process());
        assertEquals(SourceEvent.BY_RULE_TYPE, e.matchedBy());
    }

    @Test
    void 알림의_목적지는_판별자로_쓰지_않는다() {
        // R2 는 다운로드(network)와 실행(process)을 상관해 목적지와 alert.ts 의 출처가 서로 다르다.
        // 목적지로 거르면 시각과 무관한 네트워크 이벤트를 원인으로 짚게 된다.
        Map<String, Object> a = alert(1000, "DOWNLOAD_AND_EXECUTE", List.of());
        a.put("dest_ip", "203.0.113.9");

        SourceEvent e = SourceEventMatcher.match(List.of(
                networkEvent(1001, "203.0.113.9", 443),           // 목적지는 같지만 트리거가 아니다
                event(1300, "process", "evil.exe", "explorer.exe")), a);

        assertEquals("evil.exe", e.process());
        assertEquals(SourceEvent.BY_RULE_TYPE, e.matchedBy());
    }

    @Test
    void 근거요약도_못쓰고_모르는_룰이면_null() {
        Map<String, Object> a = alert(1000, "SOME_NEW_RULE", List.of());

        assertNull(SourceEventMatcher.match(List.of(event(1200, "process", "x.exe", "bash")), a));
    }

    @Test
    void 근거요약_형식이_예상과_다르면_rule_id_로_내려간다() {
        // detector 가 요약 형식을 바꿔도 엉뚱한 이벤트를 원인으로 보여 주지는 않아야 한다.
        Map<String, Object> a = alert(1000, "SCRIPT_FROM_TEMP_PATH", List.of("m1"));

        SourceEvent e = SourceEventMatcher.match(List.of(
                event(1001, "process", "noise.exe", "bash"),
                event(1300, "script", "setup.ps1", "explorer.exe")), a);

        assertEquals("setup.ps1", e.process());
        assertEquals(SourceEvent.BY_RULE_TYPE, e.matchedBy());
    }

    @Test
    void 후보가_여럿이고_거리가_같으면_먼저_일어난_것을_고른다() {
        // 판정을 유발한 원인은 판정 시각보다 앞선다.
        Map<String, Object> a = alert(1000, "SUSPICIOUS_PROCESS_CHAIN",
                List.of("process powershell.exe (parent winword.exe)"));

        SourceEvent e = SourceEventMatcher.match(List.of(
                event(1200, "process", "powershell.exe", "winword.exe"),
                event(800, "process", "powershell.exe", "winword.exe")), a);

        assertEquals(800L, e.ts());
    }

    @Test
    void 윈도우_밖의_이벤트만_있으면_null() {
        Map<String, Object> a = alert(1000, "SUSPICIOUS_PROCESS_CHAIN",
                List.of("process powershell.exe (parent winword.exe)"));
        long outside = 1000 + SourceEventMatcher.WINDOW_MS + 1;

        assertNull(SourceEventMatcher.match(
                List.of(event(outside, "process", "powershell.exe", "winword.exe")), a));
    }

    @Test
    void l7_요약이면_같은_도메인의_핸드셰이크를_고른다() {
        Map<String, Object> handshake = event(1000, "l7", "curl", "");
        handshake.put("domain", "evil.example.com");
        Map<String, Object> other = event(1000, "l7", "curl", "");
        other.put("domain", "api.github.com");
        Map<String, Object> a = alert(1000, "WEAK_TLS_HANDSHAKE",
                List.of("l7 evil.example.com (TLS 1.0)"));

        SourceEvent e = SourceEventMatcher.match(List.of(other, handshake), a);

        assertEquals("evil.example.com", e.domain());
        assertEquals(SourceEvent.BY_SUMMARY, e.matchedBy());
    }

    @Test
    void 요약이_없어도_WEAK_TLS_HANDSHAKE_는_l7_로_좁힌다() {
        Map<String, Object> handshake = event(1000, "l7", "curl", "");
        Map<String, Object> proc = event(1000, "process", "curl", "");
        Map<String, Object> a = alert(1000, "WEAK_TLS_HANDSHAKE", List.of());

        SourceEvent e = SourceEventMatcher.match(List.of(proc, handshake), a);

        assertEquals("l7", e.type());
        assertEquals(SourceEvent.BY_RULE_TYPE, e.matchedBy());
    }

    @Test
    void 이벤트가_없으면_null() {
        assertNull(SourceEventMatcher.match(List.of(), alert(1000, "SUSPICIOUS_PROCESS_CHAIN", List.of())));
    }

    @Test
    void 고른_행의_필드를_그대로_옮긴다() {
        Map<String, Object> row = networkEvent(1000, "203.0.113.9", 443);
        row.put("domain", "evil.example.com");
        row.put("detail", "{\"tls\":\"1.3\"}");
        row.put("sha256", "abc");
        Map<String, Object> a = alert(1000, "DOWNLOAD_AND_EXECUTE", List.of("network 203.0.113.9:443"));

        SourceEvent e = SourceEventMatcher.match(List.of(row), a);

        assertEquals("h1", e.host());
        assertEquals("network", e.type());
        assertEquals(1000L, e.ts());
        assertEquals("chrome.exe", e.process());
        assertEquals(443, e.destPort());
        assertEquals("evil.example.com", e.domain());
        assertEquals("{\"tls\":\"1.3\"}", e.detail());
        assertEquals("abc", e.sha256());
    }
}
