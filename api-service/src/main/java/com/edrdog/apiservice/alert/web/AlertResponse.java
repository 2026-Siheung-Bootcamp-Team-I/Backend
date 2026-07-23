package com.edrdog.apiservice.alert.web;

import com.edrdog.apiservice.alert.AlertRecord;
import com.edrdog.apiservice.alert.ThreatCatalog;

import java.util.List;

/**
 * alert 조회/상세/트리아지 응답. 목록과 상세가 같은 형태를 쓴다(matched 포함).
 * threatName 은 ruleId 를 화면 표시용 한글로 옮긴 값이다(원문 ruleId/mitre 는 유지).
 */
public record AlertResponse(
        String id,
        String host,
        String ruleId,
        String threatName,
        String mitre,
        String severity,
        String action,
        long ts,
        String status,
        List<String> matched
) {
    public static AlertResponse from(AlertRecord r) {
        return new AlertResponse(r.getId(), r.getHost(), r.getRuleId(), ThreatCatalog.threatName(r.getRuleId()),
                r.getMitre(), r.getSeverity(), r.getAction(), r.getTs(), r.getStatus(), List.copyOf(r.getMatched()));
    }
}
