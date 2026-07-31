package com.edrdog.apiservice.incident;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 알림을 프로세스 계보로 묶는 순수 로직 검증.
 *
 * <p>이 기능의 핵심 위험은 붕괴다. 바쁜 호스트에서 무관한 알림이 한 사건으로 뭉치면 조사하는 사람이
 * 엉뚱한 곳을 판다. 그래서 여기 테스트의 절반은 "묶이지 않아야 한다" 를 확인한다.
 */
class IncidentGrouperTest {

    private static final String TENANT = "1";

    /** 판정기록 한 줄. matched 의 마지막 줄이 트리거 이벤트를 짚는다(SourceEventMatcher 규약). */
    private static Map<String, Object> alert(String id, String host, long ts, String severity, String trigger) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("id", id);
        row.put("tenant_id", TENANT);
        row.put("host", host);
        row.put("rule_id", "SUSPICIOUS_PROCESS_CHAIN");
        row.put("mitre", "T1059");
        row.put("severity", severity);
        row.put("action", "notify");
        row.put("ts", String.valueOf(ts));
        row.put("matched", List.of(trigger));
        return row;
    }

    private static Map<String, Object> proc(String process, String parent, long ts, Integer pid, Integer ppid) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("type", "process");
        row.put("ts", ts);
        row.put("process", process);
        row.put("parent", parent);
        if (pid != null) {
            row.put("detail", "{\"pid\":" + pid + ",\"ppid\":" + ppid + "}");
        }
        return row;
    }

    @SafeVarargs
    private static Map<String, List<Map<String, Object>>> events(String host, Map<String, Object>... rows) {
        return Map.of(host, List.of(rows));
    }

    /**
     * 바쁜 호스트: powershell.exe 두 인스턴스가 서로 다른 부모 밑에서 각각 알림을 냈다.
     * 이름만으로 묶으면 하나가 되고, 그게 이 기능이 죽는 방식이다.
     */
    private static final List<Map<String, Object>> BUSY_ALERTS = List.of(
            alert("a1", "h1", 1_000L, "HIGH", "process powershell.exe (parent winword.exe)"),
            alert("a2", "h1", 2_000L, "MEDIUM", "process powershell.exe (parent explorer.exe)"));

    @Test
    void 바쁜_호스트의_무관한_알림은_pid_로_갈려_한_사건이_되지_않는다() {
        List<Incident> out = IncidentGrouper.group(TENANT, BUSY_ALERTS, events("h1",
                proc("winword.exe", "explorer.exe", 900L, 10, 1),
                proc("powershell.exe", "winword.exe", 1_000L, 100, 10),
                proc("powershell.exe", "explorer.exe", 2_000L, 200, 1)));

        assertEquals(2, out.size(), out.toString());
        assertEquals(1, out.get(0).alerts().size());
        assertEquals(1, out.get(1).alerts().size());
    }

    @Test
    void pid_가_없으면_같은_알림들이_한_사건으로_붕괴한다() {
        // pid 를 빼면 왜 붕괴하는지 그대로 드러난다. 이 테스트가 깨지면 pid 분리가 사라진 것이다.
        List<Incident> out = IncidentGrouper.group(TENANT, BUSY_ALERTS, events("h1",
                proc("winword.exe", "explorer.exe", 900L, null, null),
                proc("powershell.exe", "winword.exe", 1_000L, null, null),
                proc("powershell.exe", "explorer.exe", 2_000L, null, null)));

        assertEquals(1, out.size());
        assertEquals(2, out.get(0).alerts().size());
    }

    @Test
    void 조상_자손_관계인_알림은_한_사건이다() {
        List<Map<String, Object>> alerts = List.of(
                alert("a1", "h1", 1_000L, "MEDIUM", "process winword.exe (parent explorer.exe)"),
                alert("a2", "h1", 2_000L, "CRITICAL", "process powershell.exe (parent winword.exe)"));

        List<Incident> out = IncidentGrouper.group(TENANT, alerts, events("h1",
                proc("winword.exe", "explorer.exe", 1_000L, 10, 1),
                proc("powershell.exe", "winword.exe", 2_000L, 100, 10)));

        assertEquals(1, out.size());
        assertEquals(2, out.get(0).alerts().size());
        assertEquals(1_000L, out.get(0).firstTs());
        assertEquals(2_000L, out.get(0).lastTs());
        assertEquals("CRITICAL", out.get(0).severity());
        assertEquals("winword.exe", out.get(0).rootProcess());
    }

    @Test
    void 형제는_공통_조상만_같으므로_잇지_않는다() {
        // explorer.exe 밑이라는 것 말고는 둘을 잇는 관측이 없다. 이걸 이으면 호스트 하나가 사건 하나가 된다.
        List<Map<String, Object>> alerts = List.of(
                alert("a1", "h1", 1_000L, "HIGH", "process winword.exe (parent explorer.exe)"),
                alert("a2", "h1", 2_000L, "HIGH", "process chrome.exe (parent explorer.exe)"));

        List<Incident> out = IncidentGrouper.group(TENANT, alerts, events("h1",
                proc("winword.exe", "explorer.exe", 1_000L, 10, 1),
                proc("chrome.exe", "explorer.exe", 2_000L, 20, 1)));

        assertEquals(2, out.size());
    }

    @Test
    void 원본_이벤트를_못_찾은_알림은_혼자_사건이_된다() {
        List<Map<String, Object>> alerts = List.of(
                alert("a1", "h1", 1_000L, "HIGH", "process powershell.exe (parent winword.exe)"),
                alert("a2", "h1", 2_000L, "HIGH", "process ghost.exe (parent nothing.exe)"));

        List<Incident> out = IncidentGrouper.group(TENANT, alerts, events("h1",
                proc("powershell.exe", "winword.exe", 1_000L, 100, 10)));

        assertEquals(2, out.size());
        assertTrue(out.stream().anyMatch(i -> i.rootProcess().isEmpty()), out.toString());
    }

    @Test
    void 호스트가_다르면_묶지_않는다() {
        // 호스트를 잇는 관측이 없다. 프로세스 이름이 같다는 건 근거가 아니다.
        List<Map<String, Object>> alerts = List.of(
                alert("a1", "h1", 1_000L, "HIGH", "process powershell.exe (parent winword.exe)"),
                alert("a2", "h2", 1_000L, "HIGH", "process powershell.exe (parent winword.exe)"));
        Map<String, List<Map<String, Object>>> byHost = Map.of(
                "h1", List.of(proc("powershell.exe", "winword.exe", 1_000L, 100, 10)),
                "h2", List.of(proc("powershell.exe", "winword.exe", 1_000L, 100, 10)));

        List<Incident> out = IncidentGrouper.group(TENANT, alerts, byHost);

        assertEquals(2, out.size());
        assertNotEquals(out.get(0).id(), out.get(1).id());
    }

    @Test
    void 알림이_하나_더_붙어도_사건_id_는_그대로다() {
        // id 가 바뀌면 이전에 단 트리아지가 떨어져 나간다.
        List<Map<String, Object>> events = List.of(
                proc("winword.exe", "explorer.exe", 1_000L, 10, 1),
                proc("powershell.exe", "winword.exe", 2_000L, 100, 10),
                proc("cmd.exe", "powershell.exe", 3_000L, 300, 100));
        List<Map<String, Object>> before = List.of(
                alert("a1", "h1", 1_000L, "MEDIUM", "process winword.exe (parent explorer.exe)"),
                alert("a2", "h1", 2_000L, "HIGH", "process powershell.exe (parent winword.exe)"));
        List<Map<String, Object>> after = List.of(
                before.get(0), before.get(1),
                alert("a3", "h1", 3_000L, "CRITICAL", "process cmd.exe (parent powershell.exe)"));

        String idBefore = IncidentGrouper.group(TENANT, before, Map.of("h1", events)).get(0).id();
        List<Incident> grown = IncidentGrouper.group(TENANT, after, Map.of("h1", events));

        assertEquals(1, grown.size());
        assertEquals(3, grown.get(0).alerts().size());
        assertEquals(idBefore, grown.get(0).id());
    }

    @Test
    void 사건_id_는_tenant_와_host_와_최초_알림으로_결정된다() {
        List<Incident> out = IncidentGrouper.group(TENANT,
                List.of(alert("a1", "h1", 1_000L, "HIGH", "process powershell.exe (parent winword.exe)")),
                events("h1", proc("powershell.exe", "winword.exe", 1_000L, 100, 10)));

        assertEquals(IncidentId.of(TENANT, "h1", "a1"), out.get(0).id());
    }

    @Test
    void 알림이_없으면_사건도_없다() {
        assertEquals(0, IncidentGrouper.group(TENANT, List.of(), Map.of()).size());
    }

    @Test
    void 사건은_최신순으로_돌려준다() {
        List<Map<String, Object>> alerts = List.of(
                alert("a1", "h1", 1_000L, "HIGH", "process winword.exe (parent explorer.exe)"),
                alert("a2", "h1", 5_000L, "HIGH", "process chrome.exe (parent explorer.exe)"));

        List<Incident> out = IncidentGrouper.group(TENANT, alerts, events("h1",
                proc("winword.exe", "explorer.exe", 1_000L, 10, 1),
                proc("chrome.exe", "explorer.exe", 5_000L, 20, 1)));

        assertEquals(5_000L, out.get(0).firstTs());
        assertEquals(1_000L, out.get(1).firstTs());
    }

    @Test
    void 체인_노드에는_알림_사이를_잇는_중간_프로세스도_들어간다() {
        // 타임라인은 이 노드 집합으로 이벤트를 고른다. 중간 프로세스가 빠지면 전개가 끊겨 보인다.
        List<Map<String, Object>> alerts = List.of(
                alert("a1", "h1", 1_000L, "MEDIUM", "process winword.exe (parent explorer.exe)"),
                alert("a2", "h1", 3_000L, "HIGH", "process cmd.exe (parent powershell.exe)"));

        List<Incident> out = IncidentGrouper.group(TENANT, alerts, events("h1",
                proc("winword.exe", "explorer.exe", 1_000L, 10, 1),
                proc("powershell.exe", "winword.exe", 2_000L, 100, 10),
                proc("cmd.exe", "powershell.exe", 3_000L, 300, 100)));

        assertEquals(1, out.size());
        assertTrue(out.get(0).chainNodes().contains("proc:powershell.exe:100"), out.get(0).chainNodes().toString());
        // 사건의 뿌리보다 위(explorer.exe)는 알림이 없으므로 체인에 넣지 않는다
        assertTrue(out.get(0).chainNodes().stream().noneMatch(n -> n.startsWith("proc:explorer.exe")));
    }
}
