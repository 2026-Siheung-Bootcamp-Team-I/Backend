package com.edrdog.apiservice.demo;

/**
 * events 토픽 발행 스키마 사본 (detector 의 Event 와 동일 필드).
 * 데모 수집 API 가 이 형태로 발행하면 detector Kafka Streams 가 그대로 상관분석한다.
 *
 * <p>detector/archiver 모듈이 각자 사본을 두는 것과 같은 이유로 여기에도 사본을 둔다(모듈 간 의존 없음).
 * 필드명이 detector 의 Event 와 어긋나면 판정 입력이 null 로 들어가므로 바꿀 때 함께 맞춰야 한다.
 *
 * @param host      엔드포인트 식별자 (상관분석 키 = Kafka 파티션 키)
 * @param type      process | network | file | script
 * @param ts        발생 시각 (epoch millis) — detector 의 event-time 윈도우 기준
 * @param process   프로세스명/파일명 (basename)
 * @param parent    부모 프로세스명
 * @param cmdline   명령행. file/script 는 판정에 쓰는 전체 경로를 여기 담는다.
 * @param destIp    목적지 IP (network)
 * @param destPort  목적지 포트 (network)
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

    /** process 이벤트. */
    public static CollectedEvent process(String host, long ts, String process, String parent,
                                         String cmdline, String tenantId) {
        return new CollectedEvent(host, TYPE_PROCESS, ts, process, parent, cmdline, null, 0, tenantId);
    }

    /** network 이벤트. 소유 프로세스를 같이 담아야 lineage 가 process -> network 로 이어진다. */
    public static CollectedEvent network(String host, long ts, String process, String destIp,
                                         int destPort, String tenantId) {
        return new CollectedEvent(host, TYPE_NETWORK, ts, process, null, null, destIp, destPort, tenantId);
    }

    /** script 이벤트. process 는 인터프리터 basename, cmdline 은 판정용 전체 경로. */
    public static CollectedEvent script(String host, long ts, String process, String parent,
                                        String cmdline, String tenantId) {
        return new CollectedEvent(host, TYPE_SCRIPT, ts, process, parent, cmdline, null, 0, tenantId);
    }

    /** file 이벤트. process 는 파일명 basename, cmdline 은 판정용 전체 경로. */
    public static CollectedEvent file(String host, long ts, String name, String fullPath, String tenantId) {
        return new CollectedEvent(host, TYPE_FILE, ts, name, null, fullPath, null, 0, tenantId);
    }
}
