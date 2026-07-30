package com.edrdog.archiverservice.clickhouse;

import static org.assertj.core.api.Assertions.assertThat;

import com.edrdog.archiverservice.dto.Event;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

/** Event -> ClickHouse JSONEachRow 한 줄 매핑 순수 로직 검증. */
class EventRowTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void process_이벤트를_컬럼순서대로_JSON_object_로_변환한다() {
        Event e = new Event("host-1", "process", 1000L,
                "powershell.exe", "winword.exe", "-enc AAAA", null, 0, null, null, null, "tenant-a");

        String json = EventRow.toJson(e, mapper);

        assertThat(json).isEqualTo(
                "{\"host\":\"host-1\",\"tenant_id\":\"tenant-a\",\"type\":\"process\",\"ts\":1000,"
                        + "\"process\":\"powershell.exe\",\"parent\":\"winword.exe\","
                        + "\"cmdline\":\"-enc AAAA\",\"dest_ip\":\"\",\"dest_port\":0,"
                        + "\"domain\":\"\",\"detail\":\"\",\"sha256\":\"\"}");
    }

    @Test
    void null_문자열_필드는_빈문자열로_치환한다() {
        // network 이벤트: process/parent/cmdline 없음 -> ClickHouse String 컬럼에 null 대신 "" 적재
        Event e = new Event("host-2", "network", 2000L,
                null, null, null, "10.0.0.9", 4444, null, null, null, "tenant-b");

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
        Event e = new Event("host-4", "dns", 4000L,
                "curl", null, null, null, 0,
                "evil.example.com", "{\"qtype\":\"A\",\"answers\":[\"203.0.113.9\"]}", null, "tenant-a");

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
        Event e = new Event("host-5", "l7", 5000L,
                null, null, null, "203.0.113.9", 443,
                "cdn.example.com", "{\"tlsVersion\":\"1.3\",\"issuer\":\"R3\"}", null, "tenant-a");

        String json = EventRow.toJson(e, mapper);

        assertThat(json).contains("\"domain\":\"cdn.example.com\"");
        assertThat(json).contains("\"dest_port\":443");
    }

    @Test
    void tenant_id_가_null_이면_빈문자열로_치환한다() {
        Event e = new Event("host-3", "process", 3000L,
                "a.exe", "b.exe", "cmd", null, 0, null, null, null, null);

        String json = EventRow.toJson(e, mapper);

        assertThat(json).contains("\"tenant_id\":\"\"");
    }

    @Test
    void process_이벤트는_실행파일_해시를_sha256_에_싣는다() {
        // 해시로 찾는 조회의 적재쪽. collector 가 정규화한 값을 archiver 는 그대로 옮긴다.
        Event e = new Event("host-6", "process", 6000L,
                "evil.exe", "explorer.exe", "C:\\Temp\\evil.exe", null, 0, null, null,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "tenant-a");

        String json = EventRow.toJson(e, mapper);

        assertThat(json).contains(
                "\"sha256\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"");
    }
}
