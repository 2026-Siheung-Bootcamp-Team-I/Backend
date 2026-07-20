package com.edrdog.archiver.dto;

/**
 * osquery/Zeek 원시 엔드포인트 이벤트 (적재 입력 스키마). detector 의 Event 사본.
 * 여분 필드는 JsonDeserializer 가 무시하므로 원본에 필드가 더 있어도 안전.
 *
 * @param host      엔드포인트 식별자
 * @param type      이벤트 종류: "process" | "network"
 * @param ts        발생 시각 (epoch millis)
 * @param process   프로세스명 (예: powershell.exe) — process 이벤트
 * @param parent    부모 프로세스명 (예: winword.exe) — process 이벤트
 * @param cmdline   명령행
 * @param destIp    목적지 IP — network 이벤트
 * @param destPort  목적지 포트 — network 이벤트
 */
public record Event(
        String host,
        String type,
        long ts,
        String process,
        String parent,
        String cmdline,
        String destIp,
        int destPort
) {
}
