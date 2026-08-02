package com.edrdog.apiservice.demo;

/**
 * events 토픽 발행 스키마 사본 (detector 의 Event 와 동일 필드).
 * 필드명이 detector 의 Event 와 어긋나면 판정 입력이 null 로 들어가므로 바꿀 때 함께 맞춰야 한다.
 *
 * @param host      엔드포인트 식별자 (상관분석 키 = Kafka 파티션 키)
 * @param type      process | network | file | script
 * @param ts        발생 시각 (epoch millis) — detector 의 event-time 윈도우 기준
 * @param process   프로세스명/파일명 (basename)
 * @param cmdline   명령행. file/script 는 판정에 쓰는 전체 경로를 여기 담는다.
 * @param tenantId  조직(tenant) 식별자 — api-service 의 tenant PK 문자열이어야 조회에서 보인다
 */
public record CollectedEvent(
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
    public static final String TYPE_FILE = "file";
    public static final String TYPE_SCRIPT = "script";

    public static CollectedEvent process(String host, long ts, String process, String parent,
                                         String cmdline, String tenantId) {
        return new CollectedEvent(host, TYPE_PROCESS, ts, process, parent, cmdline, null, 0, tenantId);
    }

    /** 소유 프로세스를 같이 담아야 lineage 가 process -> network 로 이어진다. */
    public static CollectedEvent network(String host, long ts, String process, String destIp,
                                         int destPort, String tenantId) {
        return new CollectedEvent(host, TYPE_NETWORK, ts, process, null, null, destIp, destPort, tenantId);
    }

    /** process 는 인터프리터 basename, cmdline 은 판정용 전체 경로. */
    public static CollectedEvent script(String host, long ts, String process, String parent,
                                        String cmdline, String tenantId) {
        return new CollectedEvent(host, TYPE_SCRIPT, ts, process, parent, cmdline, null, 0, tenantId);
    }

    /** process 는 파일명 basename, cmdline 은 판정용 전체 경로. */
    public static CollectedEvent file(String host, long ts, String name, String fullPath, String tenantId) {
        return new CollectedEvent(host, TYPE_FILE, ts, name, null, fullPath, null, 0, tenantId);
    }
}
