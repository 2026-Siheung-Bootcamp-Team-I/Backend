package com.edrdog.apiservice.alert;

import com.edrdog.apiservice.alert.web.LineageResponse;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * events 행 목록 -> lineage 그래프(nodes/edges) 변환의 순수 로직 검증.
 * 이름 기반 체인이므로 같은 이름/주소는 한 노드로 합치고(dedup), 같은 엣지도 중복 제거한다.
 */
class LineageGraphBuilderTest {

    private final LineageGraphBuilder builder = new LineageGraphBuilder();

    private static Map<String, Object> process(String proc, String parent) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("type", "process");
        row.put("process", proc);
        row.put("parent", parent);
        return row;
    }

    private static Map<String, Object> network(String proc, String ip, int port) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("type", "network");
        row.put("process", proc);
        row.put("dest_ip", ip);
        row.put("dest_port", port);
        return row;
    }

    /** 에이전트가 pid/ppid 를 관측한 process 이벤트(detail JSON 에 담겨 온다). */
    private static Map<String, Object> process(String proc, String parent, int pid, int ppid) {
        Map<String, Object> row = process(proc, parent);
        row.put("detail", "{\"pid\":" + pid + ",\"ppid\":" + ppid + "}");
        return row;
    }

    private static Map<String, Object> network(String proc, String ip, int port, int pid) {
        Map<String, Object> row = network(proc, ip, port);
        row.put("detail", "{\"pid\":" + pid + "}");
        return row;
    }

    private static boolean hasNode(LineageResponse g, String id, String kind, String label) {
        return g.nodes().stream().anyMatch(n ->
                n.id().equals(id) && n.kind().equals(kind) && n.label().equals(label));
    }

    private static boolean hasEdge(LineageResponse g, String from, String to, String rel) {
        return g.edges().stream().anyMatch(e ->
                e.from().equals(from) && e.to().equals(to) && e.rel().equals(rel));
    }

    @Test
    void process_이벤트는_process_노드와_spawned_엣지를_만든다() {
        LineageResponse g = builder.build(List.of(process("powershell.exe", "winword.exe")));

        assertTrue(hasNode(g, "proc:winword.exe", "process", "winword.exe"), g.nodes().toString());
        assertTrue(hasNode(g, "proc:powershell.exe", "process", "powershell.exe"));
        assertTrue(hasEdge(g, "proc:winword.exe", "proc:powershell.exe", "spawned"));
    }

    @Test
    void parent_가_비어있으면_노드만_만들고_엣지는_없다() {
        LineageResponse g = builder.build(List.of(process("explorer.exe", "")));

        assertTrue(hasNode(g, "proc:explorer.exe", "process", "explorer.exe"));
        assertEquals(0, g.edges().size());
    }

    @Test
    void network_이벤트는_network_노드와_connected_엣지를_만든다() {
        LineageResponse g = builder.build(List.of(network("powershell.exe", "10.0.0.9", 4444)));

        assertTrue(hasNode(g, "net:10.0.0.9:4444", "network", "10.0.0.9:4444"));
        assertTrue(hasNode(g, "proc:powershell.exe", "process", "powershell.exe"));
        assertTrue(hasEdge(g, "proc:powershell.exe", "net:10.0.0.9:4444", "connected"));
    }

    @Test
    void network_소유_process_가_없으면_network_노드만_남고_엣지는_없다() {
        LineageResponse g = builder.build(List.of(network("", "10.0.0.9", 4444)));

        assertTrue(hasNode(g, "net:10.0.0.9:4444", "network", "10.0.0.9:4444"));
        assertEquals(0, g.edges().size());
    }

    @Test
    void dest_ip_가_비어있는_network_는_스킵한다() {
        LineageResponse g = builder.build(List.of(network("powershell.exe", "", 0)));

        assertTrue(g.nodes().stream().noneMatch(n -> n.kind().equals("network")));
    }

    @Test
    void 같은_이름_프로세스는_한_노드로_합친다() {
        LineageResponse g = builder.build(List.of(
                process("powershell.exe", "winword.exe"),
                process("powershell.exe", "winword.exe")));

        assertEquals(1, g.nodes().stream().filter(n -> n.id().equals("proc:powershell.exe")).count());
        assertEquals(1, g.edges().size());
    }

    @Test
    void pid_를_관측했으면_동명_프로세스를_다른_노드로_가른다() {
        // 이걸 합치면 powershell.exe 관련 알림이 전부 한 덩어리로 붕괴한다.
        LineageResponse g = builder.build(List.of(
                process("powershell.exe", "winword.exe", 100, 10),
                process("powershell.exe", "explorer.exe", 200, 20)));

        assertTrue(hasNode(g, "proc:powershell.exe:100", "process", "powershell.exe"), g.nodes().toString());
        assertTrue(hasNode(g, "proc:powershell.exe:200", "process", "powershell.exe"));
        assertTrue(hasEdge(g, "proc:winword.exe:10", "proc:powershell.exe:100", "spawned"));
        assertTrue(hasEdge(g, "proc:explorer.exe:20", "proc:powershell.exe:200", "spawned"));
    }

    @Test
    void 자식의_ppid_와_부모의_pid_는_같은_노드로_이어진다() {
        LineageResponse g = builder.build(List.of(
                process("winword.exe", "explorer.exe", 10, 1),
                process("powershell.exe", "winword.exe", 100, 10)));

        assertEquals(1, g.nodes().stream().filter(n -> n.id().equals("proc:winword.exe:10")).count());
        assertTrue(hasEdge(g, "proc:explorer.exe:1", "proc:winword.exe:10", "spawned"));
        assertTrue(hasEdge(g, "proc:winword.exe:10", "proc:powershell.exe:100", "spawned"));
        assertEquals(3, g.nodes().size());
    }

    @Test
    void network_도_pid_로_소유_프로세스를_가른다() {
        LineageResponse g = builder.build(List.of(
                process("powershell.exe", "winword.exe", 100, 10),
                network("powershell.exe", "10.0.0.9", 4444, 200)));

        // 다른 인스턴스가 낸 연결이므로 100 번에 붙으면 안 된다
        assertTrue(hasEdge(g, "proc:powershell.exe:200", "net:10.0.0.9:4444", "connected"), g.edges().toString());
        assertTrue(g.edges().stream().noneMatch(e -> e.from().equals("proc:powershell.exe:100")
                && e.rel().equals("connected")));
    }

    @Test
    void pid_를_관측하지_못한_이벤트는_예전처럼_이름으로_묶는다() {
        // 수집기가 pid 를 못 준 경우다. 이름이 마지막 수단이라 여기서 갈라 버리면 그래프가 끊긴다.
        LineageResponse g = builder.build(List.of(
                process("powershell.exe", "winword.exe"),
                process("powershell.exe", "winword.exe")));

        assertTrue(hasNode(g, "proc:powershell.exe", "process", "powershell.exe"));
        assertEquals(2, g.nodes().size());
        assertEquals(1, g.edges().size());
    }

    @Test
    void 깨진_detail_은_pid_없는_것으로_본다() {
        Map<String, Object> row = process("powershell.exe", "winword.exe");
        row.put("detail", "{not json");

        LineageResponse g = builder.build(List.of(row));

        assertTrue(hasNode(g, "proc:powershell.exe", "process", "powershell.exe"), g.nodes().toString());
    }

    @Test
    void 빈_입력이면_빈_그래프() {
        LineageResponse g = builder.build(List.of());

        assertEquals(0, g.nodes().size());
        assertEquals(0, g.edges().size());
    }

    @Test
    void 체인을_이어붙인다() {
        LineageResponse g = builder.build(List.of(
                process("winword.exe", "explorer.exe"),
                process("powershell.exe", "winword.exe"),
                network("powershell.exe", "10.0.0.9", 4444)));

        assertTrue(hasEdge(g, "proc:explorer.exe", "proc:winword.exe", "spawned"));
        assertTrue(hasEdge(g, "proc:winword.exe", "proc:powershell.exe", "spawned"));
        assertTrue(hasEdge(g, "proc:powershell.exe", "net:10.0.0.9:4444", "connected"));
        assertEquals(4, g.nodes().size());
        assertEquals(3, g.edges().size());
    }
}
