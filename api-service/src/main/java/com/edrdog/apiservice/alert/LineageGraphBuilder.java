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
 *
 * <p>프로세스 노드는 pid 로 가른다(detail JSON 의 pid/ppid). 이름만으로 합치면 동명 프로세스가
 * 한 노드가 되고, powershell.exe 처럼 흔한 이름에서는 서로 무관한 경로가 통째로 붙어 버린다.
 * 자식의 ppid 와 부모의 pid 가 같은 노드 id 를 만들어 체인이 이어진다.
 * pid 를 관측하지 못한 이벤트는 예전처럼 이름만으로 노드를 만든다(이름이 마지막 수단이라
 * 여기서 갈라 버리면 pid 없는 수집기의 그래프가 통째로 끊긴다).
 */
@Component
public class LineageGraphBuilder {

    /** detail(JSON) 파싱 전용. 읽기만 해서 공유해도 안전하고, no-arg 생성자를 유지할 수 있다. */
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * 프로세스 노드 id. pid 를 관측했으면 이름 뒤에 붙여 동명 프로세스를 가른다.
     * pid 재사용으로 다른 프로세스가 같은 id 를 받을 수 있지만, 조회 창이 분 단위라 실질적인 위험은 아니다.
     */
    public static String processNodeId(String name, Integer pid) {
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
