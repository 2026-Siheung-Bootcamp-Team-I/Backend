package com.edrdog.apiservice.incident;

import com.edrdog.apiservice.alert.LineageGraphBuilder;
import com.edrdog.apiservice.alert.SourceEventMatcher;
import com.edrdog.apiservice.alert.web.SourceEvent;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 알림들을 프로세스 계보로 묶는 순수 로직.
 *
 * <p>알림마다 그 판정을 유발한 원본 이벤트를 {@link SourceEventMatcher} 로 찾아 프로세스 노드에 건다(anchor).
 * 두 알림은 <b>anchor 가 같거나 한쪽이 다른 쪽의 조상일 때만</b> 같은 사건이다. 사건은 계보 트리 위의 한 갈래다.
 *
 * <p>시간 윈도우로 묶지 않는 이유는 명확하다. "같은 호스트 10분 안" 은 바쁜 호스트에서 무관한 알림을
 * 전부 한 덩어리로 만든다. 조상-자손은 "이 프로세스가 저 프로세스를 띄웠다" 는 관측된 사실이다.
 *
 * <p>형제(공통 조상만 같은 경우)는 잇지 않는다. 실제 호스트에서 거의 모든 프로세스는
 * explorer.exe/launchd 같은 한 뿌리로 올라가므로, 공통 조상까지 근거로 인정하면 호스트 하나가
 * 통째로 사건 하나가 된다. anchor 를 못 찾은 알림은 혼자 사건이 된다(근거 없이 옆 알림에 붙이지 않는다).
 * 호스트가 다르면 절대 묶지 않는다. 호스트를 잇는 관측이 없다.
 */
public final class IncidentGrouper {

    /** 조상을 거슬러 오를 때의 상한. pid 재사용으로 부모 관계에 고리가 생겨도 여기서 멈춘다. */
    private static final int MAX_DEPTH = 64;

    /** 사건 severity 는 구성 알림 중 가장 높은 것이다. 낮은 쪽에 맞추면 위험한 사건이 묻힌다. */
    private static final List<String> SEVERITY_ORDER = List.of("CRITICAL", "HIGH", "MEDIUM", "LOW");

    private IncidentGrouper() {
    }

    /**
     * 알림들을 사건으로 묶는다. eventsByHost 는 host 별 events 행이며, 없는 호스트는 anchor 를 못 찾아
     * 알림 하나짜리 사건이 된다. 결과는 최근 활동(lastTs) 순이다.
     */
    public static List<Incident> group(String tenantId, List<Map<String, Object>> alerts,
                                       Map<String, List<Map<String, Object>>> eventsByHost) {
        Map<String, List<Map<String, Object>>> byHost = new LinkedHashMap<>();
        for (Map<String, Object> alert : alerts) {
            byHost.computeIfAbsent(str(alert.get("host")), k -> new ArrayList<>()).add(alert);
        }
        List<Incident> out = new ArrayList<>();
        byHost.forEach((host, hostAlerts) ->
                out.addAll(onHost(tenantId, host, hostAlerts, eventsByHost.getOrDefault(host, List.of()))));
        return out.stream()
                .sorted(Comparator.comparingLong(Incident::lastTs).reversed().thenComparing(Incident::id))
                .toList();
    }

    private static List<Incident> onHost(String tenantId, String host,
                                         List<Map<String, Object>> alerts, List<Map<String, Object>> events) {
        Map<String, String> parentOf = new HashMap<>();
        Map<String, String> nameOf = new HashMap<>();
        indexProcesses(events, parentOf, nameOf);

        Map<String, String> anchorOf = new LinkedHashMap<>();   // alertId -> 프로세스 노드 id
        Map<String, List<String>> alertsByAnchor = new HashMap<>();
        for (Map<String, Object> alert : alerts) {
            String node = anchorNode(alert, events);
            if (node == null) {
                continue;
            }
            String alertId = str(alert.get("id"));
            anchorOf.put(alertId, node);
            alertsByAnchor.computeIfAbsent(node, k -> new ArrayList<>()).add(alertId);
        }

        // anchor 가 같거나 조상-자손이면 같은 사건이다. 자기 노드부터 훑으므로 같은 노드도 여기서 묶인다.
        UnionFind groups = new UnionFind();
        alerts.forEach(a -> groups.add(str(a.get("id"))));
        anchorOf.forEach((alertId, node) -> {
            for (String ancestor : ancestorPath(node, parentOf)) {
                alertsByAnchor.getOrDefault(ancestor, List.of()).forEach(other -> groups.union(alertId, other));
            }
        });

        Map<String, List<Map<String, Object>>> members = new LinkedHashMap<>();
        for (Map<String, Object> alert : alerts) {
            members.computeIfAbsent(groups.find(str(alert.get("id"))), k -> new ArrayList<>()).add(alert);
        }
        return members.values().stream()
                .map(m -> incident(tenantId, host, m, anchorOf, parentOf, nameOf))
                .toList();
    }

    /** 프로세스 노드의 부모 관계와 표시용 이름을 events 에서 뽑는다. 같은 노드가 여러 번 나오면 첫 관측을 남긴다. */
    private static void indexProcesses(List<Map<String, Object>> events,
                                       Map<String, String> parentOf, Map<String, String> nameOf) {
        for (Map<String, Object> row : events) {
            String proc = str(row.get("process"));
            if (proc.isEmpty()) {
                continue;
            }
            var detail = LineageGraphBuilder.detailOf(str(row.get("detail")));
            String nodeId = LineageGraphBuilder.processNodeId(proc, detail.pid());
            nameOf.putIfAbsent(nodeId, proc);
            String parent = str(row.get("parent"));
            if (!parent.isEmpty()) {
                String parentId = LineageGraphBuilder.processNodeId(parent, detail.ppid());
                parentOf.putIfAbsent(nodeId, parentId);
                nameOf.putIfAbsent(parentId, parent);
            }
        }
    }

    /** 알림을 걸 프로세스 노드. 원본 이벤트를 못 찾거나 그 이벤트에 프로세스가 없으면 null 이다. */
    private static String anchorNode(Map<String, Object> alert, List<Map<String, Object>> events) {
        SourceEvent source = SourceEventMatcher.match(events, alert);
        if (source == null || source.process().isBlank()) {
            return null;
        }
        return LineageGraphBuilder.processNodeId(source.process(),
                LineageGraphBuilder.detailOf(source.detail()).pid());
    }

    /** 자기 자신부터 뿌리까지의 노드들(고리가 있어도 MAX_DEPTH 에서 멈춘다). */
    private static List<String> ancestorPath(String node, Map<String, String> parentOf) {
        List<String> path = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        String current = node;
        while (current != null && path.size() < MAX_DEPTH && seen.add(current)) {
            path.add(current);
            current = parentOf.get(current);
        }
        return path;
    }

    private static Incident incident(String tenantId, String host, List<Map<String, Object>> members,
                                     Map<String, String> anchorOf, Map<String, String> parentOf,
                                     Map<String, String> nameOf) {
        List<Map<String, Object>> sorted = members.stream()
                .sorted(Comparator.comparingLong((Map<String, Object> a) -> asLong(a.get("ts")))
                        .thenComparing(a -> str(a.get("id"))))
                .toList();
        String id = IncidentId.of(tenantId, host, str(sorted.get(0).get("id")));
        long lastTs = sorted.stream().mapToLong(a -> asLong(a.get("ts"))).max().orElse(0L);
        String severity = sorted.stream().map(a -> str(a.get("severity")))
                .min(Comparator.comparingInt(IncidentGrouper::severityRank))
                .orElse("");

        List<String> anchors = sorted.stream()
                .map(a -> anchorOf.get(str(a.get("id"))))
                .filter(java.util.Objects::nonNull)
                .distinct()
                .toList();
        String top = topAnchor(anchors, parentOf);
        return new Incident(id, host, asLong(sorted.get(0).get("ts")), lastTs, severity,
                top == null ? "" : nameOf.getOrDefault(top, ""), sorted, chainNodes(anchors, parentOf));
    }

    /** 다른 anchor 를 조상으로 두지 않는 anchor(= 사건의 시작 프로세스). 계보는 트리라 하나뿐이다. */
    private static String topAnchor(List<String> anchors, Map<String, String> parentOf) {
        Set<String> anchorSet = new HashSet<>(anchors);
        return anchors.stream()
                .filter(a -> ancestorPath(a, parentOf).stream().skip(1).noneMatch(anchorSet::contains))
                .findFirst()
                .orElse(anchors.isEmpty() ? null : anchors.get(0));
    }

    /**
     * 사건에 속한 노드들: 각 anchor 에서 위로 훑되 사건의 시작 anchor 까지만 담는다.
     * 알림 사이를 잇는 중간 프로세스도 사건의 일부라 넣고(그게 빠지면 전개가 끊겨 보인다),
     * 시작 anchor 보다 위(알림이 없는 조상)는 사건 밖이라 넣지 않는다.
     */
    private static List<String> chainNodes(List<String> anchors, Map<String, String> parentOf) {
        Set<String> anchorSet = new HashSet<>(anchors);
        Set<String> chain = new LinkedHashSet<>();
        for (String anchor : anchors) {
            List<String> path = ancestorPath(anchor, parentOf);
            int last = 0;
            for (int i = 0; i < path.size(); i++) {
                if (anchorSet.contains(path.get(i))) {
                    last = i;
                }
            }
            chain.addAll(path.subList(0, last + 1));
        }
        return List.copyOf(chain);
    }

    /** 낮을수록 심각하다(정렬용). 미매핑 severity 는 가장 뒤로 보낸다. */
    private static int severityRank(String severity) {
        int i = SEVERITY_ORDER.indexOf(severity);
        return i < 0 ? SEVERITY_ORDER.size() : i;
    }

    /** 알림 id 들을 묶는 union-find. 사건 수가 작아 경로 압축만으로 충분하다. */
    private static final class UnionFind {
        private final Map<String, String> parent = new HashMap<>();

        void add(String id) {
            parent.putIfAbsent(id, id);
        }

        String find(String id) {
            String root = parent.getOrDefault(id, id);
            if (!root.equals(id)) {
                root = find(root);
                parent.put(id, root);
            }
            return root;
        }

        void union(String a, String b) {
            String ra = find(a);
            String rb = find(b);
            if (!ra.equals(rb)) {
                parent.put(rb, ra);
            }
        }
    }

    private static String str(Object v) {
        return v == null ? "" : String.valueOf(v);
    }

    private static long asLong(Object v) {
        if (v == null) {
            return 0L;
        }
        if (v instanceof Number n) {
            return n.longValue();
        }
        return Long.parseLong(String.valueOf(v));
    }
}
