package com.edrdog.apiservice.host.web;

/**
 * 대시보드 도넛용 상태 집계. 목록의 각 호스트 status 를 세어 정상/주의/위험 수와 총 관측 호스트 수를 준다.
 */
public record HostSummary(
        long healthy,
        long warning,
        long critical,
        long total
) {
}
