package com.edrdog.apiservice.alert;

/**
 * host 별 열린 alert 집계 결과(Spring Data 인터페이스 projection).
 * openTotal 은 위협수, openCritical/openHigh 는 상태 분류에 쓴다.
 */
public interface HostAlertCount {

    String getHost();

    long getOpenTotal();

    long getOpenCritical();

    long getOpenHigh();
}
