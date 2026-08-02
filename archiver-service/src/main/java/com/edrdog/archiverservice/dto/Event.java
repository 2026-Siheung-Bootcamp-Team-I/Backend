package com.edrdog.archiverservice.dto;

/**
 * 엔드포인트 에이전트가 보낸 이벤트 (적재 입력 스키마). detector 의 Event 사본.
 *
 * @param host      엔드포인트 식별자
 * @param type      이벤트 종류: "process" | "network" | "file" | "script" | "dns" | "l7"
 * @param ts        발생 시각 (epoch millis)
 * @param process   프로세스명 (예: powershell.exe) — process 이벤트. dns 는 질의를 낸 프로세스명.
 * @param parent    부모 프로세스명 (예: winword.exe) — process 이벤트
 * @param cmdline   명령행
 * @param destIp    목적지 IP — network 이벤트. l7 은 핸드셰이크 상대 IP.
 * @param destPort  목적지 포트 — network 이벤트. l7 은 핸드셰이크 상대 포트.
 * @param domain    DNS 질의 이름(dns) 또는 TLS SNI(l7)
 * @param detail    타입별 부가정보 JSON 문자열. dns 는 질의 타입/응답 IP, l7 은 인증서 발급자·주체·지문 등.
 * @param sha256    파일 해시(소문자 64자리 16진수). process/script 는 실행된 파일, file 은 그 파일의 해시.
 * @param tenantId  조직(tenant) 식별자 — 멀티테넌시 격리 태그
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
        String domain,
        String detail,
        String sha256,
        String tenantId
) {
}
