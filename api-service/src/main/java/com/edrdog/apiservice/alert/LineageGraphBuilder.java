package com.edrdog.apiservice.alert;

import com.edrdog.apiservice.alert.web.LineageResponse;
import com.edrdog.apiservice.alert.web.LineageResponse.Edge;
import com.edrdog.apiservice.alert.web.LineageResponse.Node;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * events 행 목록을 lineage 그래프(nodes/edges)로 바꾸는 순수 로직.
 *
 * <p>규칙(이름 기반):
 * <ul>
 *   <li>process 이벤트: {@code process} 노드. {@code parent} 가 있으면 parent 노드 + parent->process(spawned)</li>
 *   <li>network 이벤트: {@code dest_ip:port} 노드. 소유 {@code process} 가 있으면 process->net(connected)</li>
 * </ul>
 * 같은 노드 id / 같은 (from,to,rel) 엣지는 첫 등장만 남기고 dedup 하며, 입력 순서를 보존한다.
 * pid/ppid 가 없어 동명 프로세스는 한 노드로 합쳐진다(경로가 거칢).
 */
@Component
public class LineageGraphBuilder {

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
        String procId = putProcess(nodes, proc);
        String parent = str(row.get("parent"));
        if (!parent.isEmpty()) {
            String parentId = putProcess(nodes, parent);
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
            String procId = putProcess(nodes, proc);
            putEdge(edges, procId, netId, "connected");
        }
    }

    private static String putProcess(Map<String, Node> nodes, String name) {
        String id = "proc:" + name;
        putNode(nodes, id, "process", name);
        return id;
    }

    private static void putNode(Map<String, Node> nodes, String id, String kind, String label) {
        nodes.putIfAbsent(id, new Node(id, kind, label));
    }

    private static void putEdge(Map<String, Edge> edges, String from, String to, String rel) {
        edges.putIfAbsent(from + "->" + to + ":" + rel, new Edge(from, to, rel));
    }

    /** null/빈값을 빈 문자열로 정규화하고 앞뒤 공백을 없앤다. 숫자(dest_port)는 문자열로 변환. */
    private static String str(Object v) {
        return v == null ? "" : String.valueOf(v).trim();
    }
}
