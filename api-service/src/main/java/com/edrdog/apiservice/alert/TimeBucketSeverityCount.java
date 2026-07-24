package com.edrdog.apiservice.alert;

/**
 * 버킷×severity 별 alert 집계 결과(Spring Data 인터페이스 projection). timeseries 조립에 쓴다.
 */
public interface TimeBucketSeverityCount {

    long getBucketStart();

    String getSeverity();

    long getCnt();
}
