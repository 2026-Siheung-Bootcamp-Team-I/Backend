package com.edrdog.detectorservice.dto;

/**
 * 엔드포인트 에이전트가 보낸 이벤트 (판정 입력 스키마).
 * host 를 상관분석 키로 사용. 여분 필드는 JsonSerde 가 무시하므로 원본에 필드가 더 있어도 안전.
 *
 * @param host      엔드포인트 식별자 (상관분석 키)
 * @param type      이벤트 종류: "process" | "network" | "file" | "script" | "dns" | "l7"
 * @param ts        발생 시각 (epoch millis) — event-time 윈도우 판정 기준
 * @param process   프로세스명/파일명 (예: powershell.exe) — process/script/file 이벤트의 basename.
 *                  dns 이벤트는 질의를 낸 프로세스명.
 * @param parent    부모 프로세스명 (예: winword.exe) — process/script 이벤트
 * @param cmdline   명령행. file/script 이벤트는 판정에 쓰는 전체 경로를 여기 담는다.
 * @param destIp    목적지 IP — network 이벤트. l7 이벤트는 핸드셰이크 상대 IP.
 * @param destPort  목적지 포트 — network 이벤트. l7 이벤트는 핸드셰이크 상대 포트.
 * @param domain    DNS 질의 이름(dns) 또는 TLS SNI(l7). 검색 대상이라 detail 에 묻지 않고 별도 필드로 둔다.
 * @param detail    타입별 부가정보를 담은 JSON 문자열. dns 는 질의 타입/응답 IP 목록, l7 은 인증서
 *                  발급자·주체·지문과 TLS 버전 같은 값. 판정에 쓰는 값이 아니라 조사 화면에서 보여줄
 *                  값이라, 필드 하나가 늘 때마다 스키마를 고치지 않도록 JSON 한 칸으로 묶는다.
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
