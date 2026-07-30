package com.edrdog.archiverservice.dto;

/**
 * 엔드포인트 에이전트가 보낸 이벤트 (적재 입력 스키마). detector 의 Event 사본.
 * 여분 필드는 JsonDeserializer 가 무시하므로 원본에 필드가 더 있어도 안전.
 *
 * @param host      엔드포인트 식별자
 * @param type      이벤트 종류: "process" | "network" | "file" | "script" | "dns" | "l7"
 * @param ts        발생 시각 (epoch millis)
 * @param process   프로세스명 (예: powershell.exe) — process 이벤트. dns 는 질의를 낸 프로세스명.
 * @param parent    부모 프로세스명 (예: winword.exe) — process 이벤트
 * @param cmdline   명령행
 * @param destIp    목적지 IP — network 이벤트. l7 은 핸드셰이크 상대 IP.
 * @param destPort  목적지 포트 — network 이벤트. l7 은 핸드셰이크 상대 포트.
 * @param domain    DNS 질의 이름(dns) 또는 TLS SNI(l7). 조회 화면에서 검색 대상이라 별도 컬럼으로 적재한다.
 * @param detail    타입별 부가정보 JSON 문자열. dns 는 질의 타입/응답 IP, l7 은 인증서 발급자·주체·지문 등.
 *                  조사용 표시 값이라 컬럼을 늘리지 않고 JSON 한 칸에 담는다.
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
        String tenantId
) {
}
