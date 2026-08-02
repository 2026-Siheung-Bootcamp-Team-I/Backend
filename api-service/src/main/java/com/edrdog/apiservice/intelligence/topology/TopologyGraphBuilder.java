package com.edrdog.apiservice.intelligence.topology;

import com.edrdog.apiservice.host.HostRisk;
import com.edrdog.apiservice.intelligence.topology.web.TopologyEdge;
import com.edrdog.apiservice.intelligence.topology.web.TopologyNode;
import com.edrdog.apiservice.intelligence.topology.web.TopologyResponse;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * 관계 집계 결과를 그래프(노드/엣지)로 조립하는 순수 로직.
 * 관계 목록의 순서(이벤트 많은 순)를 그대로 유지해 프론트가 그리는 순서가 매번 같도록 한다.
 */
public final class TopologyGraphBuilder {

    private TopologyGraphBuilder() {
    }

    public static TopologyResponse build(long from, long to, long totalRelations,
                                         List<EgressRelation> relations,
                                         List<RelationAlertCount> alertCounts,
                                         List<HostRisk> risks) {
        Map<List<String>, Long> alertsByRelation = alertCounts.stream()
                .collect(Collectors.toMap(c -> key(c.host(), c.dest()), RelationAlertCount::alerts,
                        (a, b) -> a + b));
        Map<String, HostRisk> riskByHost = risks.stream()
                .collect(Collectors.toMap(HostRisk::host, Function.identity(), (a, b) -> a));

        Set<String> hosts = new LinkedHashSet<>();
        Map<String, String> destKinds = new LinkedHashMap<>();
        List<TopologyEdge> edges = new ArrayList<>();
        for (EgressRelation r : relations) {
            hosts.add(r.host());
            destKinds.putIfAbsent(r.dest(), r.destKind());
            edges.add(new TopologyEdge("host:" + r.host(), "dest:" + r.dest(), r.events(),
                    alertsByRelation.getOrDefault(key(r.host(), r.dest()), 0L), r.protocols(), r.lastSeen()));
        }

        Map<String, String> groupByDest = groupDestinations(destKinds.keySet());
        List<TopologyNode> nodes = new ArrayList<>();
        for (String host : hosts) {
            HostRisk risk = riskByHost.get(host);
            nodes.add(TopologyNode.endpoint(host, risk == null ? 0 : risk.score(),
                    risk == null ? 0 : risk.total()));
        }
        destKinds.forEach((dest, kind) -> {
            String group = groupByDest.get(dest);
            nodes.add(TopologyNode.destination(dest, kind, group == null ? null : "group:" + group));
        });
        groupSizes(groupByDest).forEach((group, members) -> nodes.add(TopologyNode.domainGroup(group, members)));

        return new TopologyResponse(from, to, totalRelations, relations.size(),
                relations.size() < totalRelations, nodes, edges);
    }

    /** 목적지를 등록가능 도메인(eTLD+1)별로 묶는다. 원소가 하나뿐인 묶음은 상자만 늘고 알려 주는 것이 없어 만들지 않는다. */
    private static Map<String, String> groupDestinations(Set<String> destinations) {
        Map<String, List<String>> byDomain = new LinkedHashMap<>();
        for (String dest : destinations) {
            Optional<String> registrable = RegistrableDomain.of(dest);
            registrable.ifPresent(d -> byDomain.computeIfAbsent(d, k -> new ArrayList<>()).add(dest));
        }
        Map<String, String> groupByDest = new LinkedHashMap<>();
        byDomain.forEach((domain, members) -> {
            if (members.size() > 1) {
                members.forEach(dest -> groupByDest.put(dest, domain));
            }
        });
        return groupByDest;
    }

    /** 그룹별 소속 목적지 수(그룹 노드 표시용). 순서는 목적지 등장 순서를 따른다. */
    private static Map<String, Integer> groupSizes(Map<String, String> groupByDest) {
        Map<String, Integer> sizes = new LinkedHashMap<>();
        groupByDest.values().forEach(group -> sizes.merge(group, 1, Integer::sum));
        return sizes;
    }

    /** (host, 목적지) 합성 키. 문자열을 이어 붙이지 않는 이유는 구분자로 쓸 안전한 문자가 없어서다. */
    private static List<String> key(String host, String dest) {
        return List.of(host, dest);
    }
}
