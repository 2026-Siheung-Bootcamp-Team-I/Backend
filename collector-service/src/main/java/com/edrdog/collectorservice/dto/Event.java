package com.edrdog.collectorservice.dto;

/**
 * detector/archiver 가 소비하는 정규화된 이벤트 스키마 (collector 출력). detector 의 Event 사본.
 *
 * @param host      엔드포인트 식별자 (상관분석 키)
 * @param type      이벤트 종류: "process" | "network"
 * @param ts        발생 시각 (epoch millis)
 * @param process   프로세스명 (예: powershell.exe)
 * @param parent    부모 프로세스명 (예: winword.exe)
 * @param cmdline   명령행
 * @param destIp    목적지 IP — network 이벤트
 * @param destPort  목적지 포트 — network 이벤트
 * @param tenantId  조직(tenant) 식별자 — 멀티테넌시 격리 태그. 수집 API 가 node_key 로 풀어 루트에 태깅한 값을 그대로 흘린다.
 */
public record Event(
        String host,
        String type,
        long ts,
        String process,
        String parent,
        String cmdline,
        String destIp,
        int destPort,
        String tenantId
) {
    public static final String TYPE_PROCESS = "process";
    public static final String TYPE_NETWORK = "network";
}
