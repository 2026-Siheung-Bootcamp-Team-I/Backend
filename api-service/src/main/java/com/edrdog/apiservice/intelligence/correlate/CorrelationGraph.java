package com.edrdog.apiservice.intelligence.correlate;

import java.util.List;

/** 상관분석 결과 그래프. */
public record CorrelationGraph(List<CorrelationNode> nodes, List<CorrelationEdge> edges) {
}
