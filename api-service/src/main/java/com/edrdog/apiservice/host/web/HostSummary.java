package com.edrdog.apiservice.host.web;

/**
 * 대시보드 도넛용 상태 집계. 목록의 각 호스트 status 를 세어 정상/주의/위험 수와 총 호스트 수를 준다.
 * 등록만 되고 이벤트가 한 번도 없는 기기는 "정상"이 아니라 "아직 모름"이라 healthy 에서 빼서 noEvents 로 따로 센다.
 * healthy + warning + critical + noEvents == total 이 항상 성립한다.
 */
public record HostSummary(
        long healthy,
        long warning,
        long critical,
        long total,
        long noEvents
) {
}
