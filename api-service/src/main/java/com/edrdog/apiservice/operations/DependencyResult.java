package com.edrdog.apiservice.operations;

/** 의존 저장소(mysql/kafka/clickhouse) 도달 여부. status: up | down | unknown. */
public record DependencyResult(String name, String status, String error) {

    public static DependencyResult up(String name) {
        return new DependencyResult(name, "up", null);
    }

    public static DependencyResult down(String name, String error) {
        return new DependencyResult(name, "down", error);
    }

    public static DependencyResult unknown(String name, String note) {
        return new DependencyResult(name, "unknown", note);
    }
}
