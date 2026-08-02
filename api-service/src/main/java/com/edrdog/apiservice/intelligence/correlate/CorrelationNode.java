package com.edrdog.apiservice.intelligence.correlate;

/** 그래프 꼭짓점 하나. id 에서 kind 를 빼면 도메인 "foo" 와 호스트 이름 "foo" 가 한 노드로 겹친다. */
public record CorrelationNode(String id, NodeKind kind, String value) {

    public static CorrelationNode of(NodeKind kind, String value) {
        return new CorrelationNode(id(kind, value), kind, value);
    }

    public static String id(NodeKind kind, String value) {
        return kind.name().toLowerCase(java.util.Locale.ROOT) + ":" + value;
    }
}
