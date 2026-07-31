package com.edrdog.apiservice.operations;

/**
 * ClickHouse 테이블 하나의 최근 적재 상태.
 * status: up(계산됨) | unknown(테이블이 비어 있어 지연을 잴 기준이 없음) | down(조회 자체가 실패).
 * lagSeconds 는 unknown/down 이면 null 이다(0으로 채우면 "방금 적재됨"처럼 보인다).
 */
public record ClickHouseIngestionResult(String table, Long lagSeconds, long recentCount, String status,
                                        String error) {

    public static ClickHouseIngestionResult of(String table, Long lagSeconds, long recentCount) {
        return new ClickHouseIngestionResult(table, lagSeconds, recentCount, lagSeconds == null ? "unknown" : "up",
                null);
    }

    public static ClickHouseIngestionResult error(String table, String error) {
        return new ClickHouseIngestionResult(table, null, 0, "down", error);
    }
}
