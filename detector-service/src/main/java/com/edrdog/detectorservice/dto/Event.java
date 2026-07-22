package com.edrdog.detectorservice.dto;

/**
 * osquery/Zeek 원시 엔드포인트 이벤트 (판정 입력 스키마).
 * host 를 상관분석 키로 사용. 여분 필드는 JsonSerde 가 무시하므로 원본에 필드가 더 있어도 안전.
 *
 * @param host      엔드포인트 식별자 (상관분석 키)
 * @param type      이벤트 종류: "process" | "network"
 * @param ts        발생 시각 (epoch millis) — event-time 윈도우 판정 기준
 * @param process   프로세스명 (예: powershell.exe) — process 이벤트
 * @param parent    부모 프로세스명 (예: winword.exe) — process 이벤트
 * @param cmdline   명령행
 * @param destIp    목적지 IP — network 이벤트
 * @param destPort  목적지 포트 — network 이벤트
 * @param tenantId  조직(tenant) 식별자 — 멀티테넌시 격리 태그. 판정에는 쓰지 않고 태그로만 흐른다.
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
