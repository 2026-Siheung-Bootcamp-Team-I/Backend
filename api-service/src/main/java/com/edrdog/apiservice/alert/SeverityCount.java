package com.edrdog.apiservice.alert;

/**
 * severity 별 alert 집계 결과(Spring Data 인터페이스 projection). summary 의 분포 계산에 쓴다.
 */
public interface SeverityCount {

    String getSeverity();

    long getCnt();
}
