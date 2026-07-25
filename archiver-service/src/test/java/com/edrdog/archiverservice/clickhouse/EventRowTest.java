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
                "powershell.exe", "winword.exe", "-enc AAAA", null, 0, "tenant-a");

        String json = EventRow.toJson(e, mapper);

        assertThat(json).isEqualTo(
                "{\"host\":\"host-1\",\"tenant_id\":\"tenant-a\",\"type\":\"process\",\"ts\":1000,"
                        + "\"process\":\"powershell.exe\",\"parent\":\"winword.exe\","
                        + "\"cmdline\":\"-enc AAAA\",\"dest_ip\":\"\",\"dest_port\":0}");
    }

    @Test
    void null_문자열_필드는_빈문자열로_치환한다() {
        // network 이벤트: process/parent/cmdline 없음 -> ClickHouse String 컬럼에 null 대신 "" 적재
        Event e = new Event("host-2", "network", 2000L,
                null, null, null, "10.0.0.9", 4444, "tenant-b");

        String json = EventRow.toJson(e, mapper);

        assertThat(json).isEqualTo(
                "{\"host\":\"host-2\",\"tenant_id\":\"tenant-b\",\"type\":\"network\",\"ts\":2000,"
                        + "\"process\":\"\",\"parent\":\"\",\"cmdline\":\"\","
                        + "\"dest_ip\":\"10.0.0.9\",\"dest_port\":4444}");
    }

    @Test
    void tenant_id_가_null_이면_빈문자열로_치환한다() {
        Event e = new Event("host-3", "process", 3000L,
                "a.exe", "b.exe", "cmd", null, 0, null);

        String json = EventRow.toJson(e, mapper);

        assertThat(json).contains("\"tenant_id\":\"\"");
    }
}
