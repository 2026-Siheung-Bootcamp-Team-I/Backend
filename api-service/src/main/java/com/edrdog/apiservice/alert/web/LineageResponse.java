package com.edrdog.apiservice.alert.web;

import java.util.List;

/**
 * alert 하나의 공격 경로(process lineage) 그래프 응답. 프론트는 nodes/edges 를 트리로 그린다.
 */
public record LineageResponse(List<Node> nodes, List<Edge> edges) {

    /**
     * 그래프 노드.
     *
     * @param id    dedup 키 겸 식별자 ({@code proc:<name>} 또는 {@code net:<ip>:<port>})
     * @param kind  process | file | network (file 은 현재 미발생)
     * @param label 화면 표시용 이름/주소
     */
    public record Node(String id, String kind, String label) {
    }

    /**
     * 그래프 엣지.
     *
     * @param from 출발 노드 id
     * @param to   도착 노드 id
     * @param rel  spawned | wrote | connected (wrote 는 현재 미발생)
     */
    public record Edge(String from, String to, String rel) {
    }
}
