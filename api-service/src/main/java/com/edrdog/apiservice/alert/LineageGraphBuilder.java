package com.edrdog.apiservice.alert;

import com.edrdog.apiservice.alert.web.LineageResponse;
import com.edrdog.apiservice.alert.web.LineageResponse.Edge;
import com.edrdog.apiservice.alert.web.LineageResponse.Node;
import com.edrdog.apiservice.web.EventDetail;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * events 행 목록을 lineage 그래프(nodes/edges)로 바꾸는 순수 로직.
 *
 * <p>규칙:
 * <ul>
 *   <li>process 이벤트: {@code process} 노드. {@code parent} 가 있으면 parent 노드 + parent->process(spawned)</li>
 *   <li>network 이벤트: {@code dest_ip:port} 노드. 소유 {@code process} 가 있으면 process->net(connected)</li>
 * </ul>
 * 같은 노드 id / 같은 (from,to,rel) 엣지는 첫 등장만 남기고 dedup 하며, 입력 순서를 보존한다.
 */
@Component
public class LineageGraphBuilder {

    // 읽기만 해서 공유해도 안전하다. 인스턴스 필드로 내리면 no-arg 생성자를 못 쓴다.
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** 프로세스 노드 id. */
    // pid 를 안 붙이면 powershell.exe 같은 흔한 이름에서 서로 무관한 경로가 한 노드로 붙는다.
    public static String processNodeId(String name, Integer pid) {
        // pid 없는 쪽도 갈라 버리면 pid 를 못 보내는 수집기의 그래프가 통째로 끊긴다.
        return pid == null ? "proc:" + name : "proc:" + name + ":" + pid;
    }

    /** events.detail(JSON)을 편 것. 관측하지 못한 값은 null 이다(EventDetail 규칙). */
    public static EventDetail detailOf(String rawDetail) {
        return EventDetail.parse(rawDetail, MAPPER);
    }

    private static EventDetail detailOf(Map<String, Object> row) {
        return detailOf(str(row.get("detail")));
    }

    public LineageResponse build(List<Map<String, Object>> rows) {
        Map<String, Node> nodes = new LinkedHashMap<>();
        Map<String, Edge> edges = new LinkedHashMap<>();

        for (Map<String, Object> row : rows) {
            if ("network".equals(str(row.get("type")))) {
                addNetwork(row, nodes, edges);
            } else {
                addProcess(row, nodes, edges);
            }
        }
        return new LineageResponse(List.copyOf(nodes.values()), List.copyOf(edges.values()));
    }

    private static void addProcess(Map<String, Object> row, Map<String, Node> nodes, Map<String, Edge> edges) {
        String proc = str(row.get("process"));
        if (proc.isEmpty()) {
            return;
        }
        EventDetail detail = detailOf(row);
        String procId = putProcess(nodes, proc, detail.pid());
        String parent = str(row.get("parent"));
        if (!parent.isEmpty()) {
            String parentId = putProcess(nodes, parent, detail.ppid());
            putEdge(edges, parentId, procId, "spawned");
        }
    }

    private static void addNetwork(Map<String, Object> row, Map<String, Node> nodes, Map<String, Edge> edges) {
        String ip = str(row.get("dest_ip"));
        if (ip.isEmpty()) {
            return;
        }
        String target = ip + ":" + str(row.get("dest_port"));
        String netId = "net:" + target;
        putNode(nodes, netId, "network", target);
        String proc = str(row.get("process"));
        if (!proc.isEmpty()) {
            String procId = putProcess(nodes, proc, detailOf(row).pid());
            putEdge(edges, procId, netId, "connected");
        }
    }

    private static String putProcess(Map<String, Node> nodes, String name, Integer pid) {
        String id = processNodeId(name, pid);
        putNode(nodes, id, "process", name);
        return id;
    }

    private static void putNode(Map<String, Node> nodes, String id, String kind, String label) {
        nodes.putIfAbsent(id, new Node(id, kind, label));
    }

    private static void putEdge(Map<String, Edge> edges, String from, String to, String rel) {
        edges.putIfAbsent(from + "->" + to + ":" + rel, new Edge(from, to, rel));
    }

    private static String str(Object v) {
        return v == null ? "" : String.valueOf(v).trim();
    }
}
