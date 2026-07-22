package com.edrdog.apiservice.alert.web;

import com.edrdog.apiservice.alert.AlertRecord;

import java.util.List;

/**
 * alert 조회/상세/트리아지 응답. 목록과 상세가 같은 형태를 쓴다(matched 포함).
 */
public record AlertResponse(
        String id,
        String host,
        String ruleId,
        String mitre,
        String severity,
        String action,
        long ts,
        String status,
        List<String> matched
) {
    public static AlertResponse from(AlertRecord r) {
        return new AlertResponse(r.getId(), r.getHost(), r.getRuleId(), r.getMitre(),
                r.getSeverity(), r.getAction(), r.getTs(), r.getStatus(), List.copyOf(r.getMatched()));
    }
}
