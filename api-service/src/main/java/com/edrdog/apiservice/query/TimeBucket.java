package com.edrdog.apiservice.query;

/**
 * timeseries 한 버킷의 집계 결과. bucketStart 는 버킷 시작 시각(epoch millis, UTC 정렬),
 * count 는 미분류 severity 까지 포함한 전체 건수다.
 */
public record TimeBucket(long bucketStart, long critical, long high, long medium, long count) {
}
