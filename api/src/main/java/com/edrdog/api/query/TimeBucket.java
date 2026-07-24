package com.edrdog.api.query;

import java.util.Map;

/**
 * timeseries 한 버킷의 집계 결과. bucketStart 는 버킷 시작 시각(epoch millis, UTC 정렬).
 */
public record TimeBucket(long bucketStart, long critical, long high, long count) {

    /** ClickHouse FORMAT JSON 행(UInt64 는 문자열로 옴)을 파싱한다. */
    public static TimeBucket fromRow(Map<String, Object> row) {
        return new TimeBucket(
                asLong(row.get("bucketStart")),
                asLong(row.get("critical")),
                asLong(row.get("high")),
                asLong(row.get("count")));
    }

    private static long asLong(Object v) {
        return v == null ? 0L : Long.parseLong(String.valueOf(v));
    }
}
