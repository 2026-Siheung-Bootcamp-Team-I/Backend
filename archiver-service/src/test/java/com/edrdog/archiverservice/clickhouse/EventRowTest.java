package com.edrdog.archiverservice.clickhouse;

import static org.assertj.core.api.Assertions.assertThat;

import com.edrdog.schema.Event;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * 적재되는 한 줄이 Protobuf 전환 전후로 같아야 한다. ClickHouse 테이블은 그대로이기 때문이다.
 * proto3 에는 null 이 없어 관측 못 한 문자열이 빈 값으로 오는데, 예전 null 치환 결과와 같은 자리다.
 */
class EventRowTest {

    private final ObjectMapper mapper = new ObjectMapper();

    private static Event.Builder event(String host, String type, long ts, String tenantId) {
        return Event.newBuilder().setHost(host).setType(type).setTs(ts).setTenantId(tenantId);
    }

    @Test
    void process_이벤트를_컬럼순서대로_JSON_object_로_변환한다() {
        Event e = event("host-1", "process", 1000L, "tenant-a")
                .setProcess("powershell.exe").setParent("winword.exe").setCmdline("-enc AAAA")
                .build();

        String json = EventRow.toJson(e, mapper);

        assertThat(json).isEqualTo(
                "{\"host\":\"host-1\",\"tenant_id\":\"tenant-a\",\"type\":\"process\",\"ts\":1000,"
                        + "\"process\":\"powershell.exe\",\"parent\":\"winword.exe\","
                        + "\"cmdline\":\"-enc AAAA\",\"dest_ip\":\"\",\"dest_port\":0,"
                        + "\"domain\":\"\",\"detail\":\"\",\"sha256\":\"\"}");
    }

    @Test
    void 관측_못_한_문자열_필드는_빈문자열로_적재한다() {
        // network 이벤트: process/parent/cmdline 없음 -> ClickHouse String 컬럼에 "" 적재
        Event e = event("host-2", "network", 2000L, "tenant-b")
                .setDestIp("10.0.0.9").setDestPort(4444)
                .build();

        String json = EventRow.toJson(e, mapper);

        assertThat(json).isEqualTo(
                "{\"host\":\"host-2\",\"tenant_id\":\"tenant-b\",\"type\":\"network\",\"ts\":2000,"
                        + "\"process\":\"\",\"parent\":\"\",\"cmdline\":\"\","
                        + "\"dest_ip\":\"10.0.0.9\",\"dest_port\":4444,"
                        + "\"domain\":\"\",\"detail\":\"\",\"sha256\":\"\"}");
    }

    @Test
    void dns_이벤트는_domain_과_detail_을_그대로_싣는다() {
        // detail 은 JSON 문자열 한 칸. archiver 는 구조를 해석하지 않고 문자열 그대로 적재한다.
        Event e = event("host-4", "dns", 4000L, "tenant-a")
                .setProcess("curl")
                .setDomain("evil.example.com")
                .setDetail("{\"qtype\":\"A\",\"answers\":[\"203.0.113.9\"]}")
                .build();

        String json = EventRow.toJson(e, mapper);

        assertThat(json).isEqualTo(
                "{\"host\":\"host-4\",\"tenant_id\":\"tenant-a\",\"type\":\"dns\",\"ts\":4000,"
                        + "\"process\":\"curl\",\"parent\":\"\",\"cmdline\":\"\","
                        + "\"dest_ip\":\"\",\"dest_port\":0,"
                        + "\"domain\":\"evil.example.com\","
                        + "\"detail\":\"{\\\"qtype\\\":\\\"A\\\",\\\"answers\\\":[\\\"203.0.113.9\\\"]}\","
                        + "\"sha256\":\"\"}");
    }

    @Test
    void l7_이벤트는_SNI_를_domain_에_싣는다() {
        Event e = event("host-5", "l7", 5000L, "tenant-a")
                .setDestIp("203.0.113.9").setDestPort(443)
                .setDomain("cdn.example.com")
                .setDetail("{\"tlsVersion\":\"1.3\",\"issuer\":\"R3\"}")
                .build();

        String json = EventRow.toJson(e, mapper);

        assertThat(json).contains("\"domain\":\"cdn.example.com\"");
        assertThat(json).contains("\"dest_port\":443");
    }

    @Test
    void tenant_id_가_비어도_빈문자열로_적재한다() {
        Event e = event("host-3", "process", 3000L, "")
                .setProcess("a.exe").setParent("b.exe").setCmdline("cmd")
                .build();

        String json = EventRow.toJson(e, mapper);

        assertThat(json).contains("\"tenant_id\":\"\"");
    }

    @Test
    void process_이벤트는_실행파일_해시를_sha256_에_싣는다() {
        // 해시로 찾는 조회의 적재쪽. collector 가 정규화한 값을 archiver 는 그대로 옮긴다.
        Event e = event("host-6", "process", 6000L, "tenant-a")
                .setProcess("evil.exe").setParent("explorer.exe").setCmdline("C:\\Temp\\evil.exe")
                .setSha256("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .build();

        String json = EventRow.toJson(e, mapper);

        assertThat(json).contains(
                "\"sha256\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"");
    }

    @Test
    void 여러_건은_개행으로_이어붙인다() {
        Event a = event("host-1", "process", 1000L, "tenant-a").setProcess("a.exe").build();
        Event b = event("host-2", "process", 2000L, "tenant-a").setProcess("b.exe").build();

        String rows = EventRow.toJsonRows(List.of(a, b), mapper);

        assertThat(rows).isEqualTo(
                EventRow.toJson(a, mapper) + "\n" + EventRow.toJson(b, mapper));
    }

    @Test
    void 한_건이면_개행이_붙지_않는다() {
        Event a = event("host-1", "process", 1000L, "tenant-a").setProcess("a.exe").build();

        String rows = EventRow.toJsonRows(List.of(a), mapper);

        assertThat(rows).isEqualTo(EventRow.toJson(a, mapper));
        assertThat(rows).doesNotContain("\n");
    }
}
