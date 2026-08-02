package com.edrdog.apiservice.alert;

/** host 별 열린 alert 집계 결과. openTotal 은 위협수, openCritical/openHigh 는 상태 분류에 쓴다. */
public record HostAlertCount(String host, long openTotal, long openCritical, long openHigh) {
}
