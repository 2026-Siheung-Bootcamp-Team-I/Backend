package com.edrdog.apiservice.query;

/**
 * timeseries 한 버킷의 집계 결과. bucketStart 는 버킷 시작 시각(epoch millis, UTC 정렬).
 * severity 별 카운트(critical/high/medium)와 전체 count 를 담는다(count 는 미분류 severity 도 포함).
 */
public record TimeBucket(long bucketStart, long critical, long high, long medium, long count) {
}
