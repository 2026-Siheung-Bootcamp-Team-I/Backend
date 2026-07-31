package com.edrdog.apiservice.intelligence.topology.web;

import java.util.List;

/**
 * GET /api/intelligence/topology 응답. 프론트는 nodes/edges 를 그래프로 그린다.
 *
 * @param totalRelations 자르기 전 전체 관계 수
 * @param shownRelations 실제로 담은 관계 수. totalRelations 와 함께 줘야 화면이 "이게 전부" 로 읽히지 않는다
 * @param truncated      Top-N 으로 잘렸는지
 */
public record TopologyResponse(long from, long to, long totalRelations, int shownRelations, boolean truncated,
                               List<TopologyNode> nodes, List<TopologyEdge> edges) {
}
