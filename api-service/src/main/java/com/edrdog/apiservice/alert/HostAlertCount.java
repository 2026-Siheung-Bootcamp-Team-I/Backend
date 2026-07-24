package com.edrdog.apiservice.alert;

/**
 * host 별 열린 alert 집계 결과. 예전엔 MySQL 인터페이스 projection 이었으나,
 * 집계가 ClickHouse 로 옮겨가면서 CH 행(Map)에서 만드는 단순 값 객체로 바꿨다.
 * openTotal 은 위협수, openCritical/openHigh 는 상태 분류에 쓴다.
 */
public record HostAlertCount(String host, long openTotal, long openCritical, long openHigh) {
}
