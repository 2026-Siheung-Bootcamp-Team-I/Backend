package com.edrdog.apiservice.intelligence.correlate;

/**
 * 그래프 꼭짓점 하나. id 는 kind 와 value 로 만들어 종류가 다르면 같은 문자열이어도 안 겹친다
 * (예: 도메인 "foo" 와 호스트 이름 "foo").
 */
public record CorrelationNode(String id, NodeKind kind, String value) {

    public static CorrelationNode of(NodeKind kind, String value) {
        return new CorrelationNode(id(kind, value), kind, value);
    }

    public static String id(NodeKind kind, String value) {
        return kind.name().toLowerCase(java.util.Locale.ROOT) + ":" + value;
    }
}
