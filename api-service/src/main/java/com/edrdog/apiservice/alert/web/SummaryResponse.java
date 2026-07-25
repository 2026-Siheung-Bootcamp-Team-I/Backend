package com.edrdog.apiservice.alert.web;

import java.util.List;

/**
 * alert 대시보드 집계 응답. total 은 기간 내 총 alert 수, severity 는 3단계 분포,
 * topThreats 는 카테고리별 상위 위협이다(count 내림차순).
 */
public record SummaryResponse(long total, Severity severity, List<ThreatCount> topThreats) {

    /**
     * severity 3단계 분포. 현재 데이터에는 MEDIUM 이 없어 medium 은 사실상 항상 0 이다.
     */
    public record Severity(long critical, long high, long medium) {
    }

    /** 카테고리별 위협 건수. */
    public record ThreatCount(String category, long count) {
    }
}
