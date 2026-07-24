package com.edrdog.apiservice.demo;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * 데모 시드용 events 행. ClickHouse(edrdog.events) 컬럼과 1:1 로 맞춘 JSONEachRow 스키마다.
 * archiver 의 EventRow 와 같은 모양이지만, 시드는 Kafka 를 거치지 않고 직접 적재하므로 여기 따로 둔다.
 *
 * @param host     엔드포인트 식별자
 * @param tenantId 조직(tenant) 식별자 문자열 (조회 격리 키)
 * @param type     process | network | file | script
 * @param ts       발생 시각 (epoch millis)
 * @param process  프로세스명/파일명
 * @param parent   부모 프로세스명
 * @param cmdline  명령행 (file/script 는 전체 경로)
 * @param destIp   목적지 IP (network)
 * @param destPort 목적지 포트 (network)
 */
public record DemoEvent(
        @JsonProperty("host") String host,
        @JsonProperty("tenant_id") String tenantId,
        @JsonProperty("type") String type,
        @JsonProperty("ts") long ts,
        @JsonProperty("process") String process,
        @JsonProperty("parent") String parent,
        @JsonProperty("cmdline") String cmdline,
        @JsonProperty("dest_ip") String destIp,
        @JsonProperty("dest_port") int destPort
) {

    public static final String TYPE_PROCESS = "process";
    public static final String TYPE_NETWORK = "network";
    public static final String TYPE_FILE = "file";
    public static final String TYPE_SCRIPT = "script";

    /** process/script/file 계열 이벤트. ClickHouse 는 Nullable 이 아니므로 빈 문자열로 채운다. */
    public static DemoEvent of(String host, String tenantId, String type, long ts,
                               String process, String parent, String cmdline) {
        return new DemoEvent(host, tenantId, type, ts, nz(process), nz(parent), nz(cmdline), "", 0);
    }

    /** network 이벤트. 소유 프로세스를 같이 담아야 lineage 가 process -> net 으로 이어진다. */
    public static DemoEvent network(String host, String tenantId, long ts,
                                    String process, String destIp, int destPort) {
        return new DemoEvent(host, tenantId, TYPE_NETWORK, ts, nz(process), "", "", nz(destIp), destPort);
    }

    private static String nz(String v) {
        return v == null ? "" : v;
    }
}
