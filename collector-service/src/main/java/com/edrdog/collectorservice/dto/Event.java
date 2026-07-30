package com.edrdog.collectorservice.dto;

/**
 * detector/archiver 가 소비하는 정규화된 이벤트 스키마 (collector 출력). detector 의 Event 사본.
 *
 * @param host      엔드포인트 식별자 (상관분석 키)
 * @param type      이벤트 종류: "process" | "network" | "file" | "script" | "dns" | "l7"
 * @param ts        발생 시각 (epoch millis)
 * @param process   프로세스명/파일명 (예: powershell.exe). dns 는 질의를 낸 프로세스명.
 * @param parent    부모 프로세스명 (예: winword.exe)
 * @param cmdline   명령행. file/script 이벤트는 판정용 전체 경로를 담는다.
 * @param destIp    목적지 IP — network 이벤트. l7 은 핸드셰이크 상대 IP.
 * @param destPort  목적지 포트 — network 이벤트. l7 은 핸드셰이크 상대 포트.
 * @param domain    DNS 질의 이름(dns) 또는 TLS SNI(l7). dns/l7 은 이 값이 없으면 쓸모가 없어 검증에서 거른다.
 * @param detail    타입별 부가정보 JSON 문자열. dns 는 질의 타입/응답 IP, l7 은 인증서 발급자·주체·지문 등.
 *                  값의 구조는 검증하지 않고 문자열 그대로 흘린다.
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
        String domain,
        String detail,
        String tenantId
) {
    public static final String TYPE_PROCESS = "process";
    public static final String TYPE_NETWORK = "network";
    public static final String TYPE_FILE = "file";
    public static final String TYPE_SCRIPT = "script";
    public static final String TYPE_DNS = "dns";
    public static final String TYPE_L7 = "l7";
}
