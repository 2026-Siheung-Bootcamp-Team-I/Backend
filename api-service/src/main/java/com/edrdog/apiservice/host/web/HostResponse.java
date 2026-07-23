package com.edrdog.apiservice.host.web;

/**
 * 엔드포인트(호스트) 목록 한 행. status 는 영문 enum(healthy|warning|critical),
 * threats 는 열린 alert 총수, lastSeen 은 events 최신 ts(epoch millis).
 */
public record HostResponse(
        String host,
        long lastSeen,
        String status,
        long threats
) {
}
