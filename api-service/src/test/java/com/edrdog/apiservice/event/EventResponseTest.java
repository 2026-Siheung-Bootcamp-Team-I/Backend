package com.edrdog.apiservice.event;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * ClickHouse events 행(Map) -> EventResponse 매핑 검증.
 * ts 는 ClickHouse 가 UInt64 를 JSON 에서 문자열로 주므로 숫자/문자열 양쪽을 다뤄야 하고,
 * detail 이 비어 있거나 깨져도 나머지 컬럼은 그대로 살아 있어야 한다(AlertResponse.asLong 과 같은 원칙).
 */
class EventResponseTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void 행을_DTO_로_변환하고_detail_원본_문자열도_남긴다() {
        Map<String, Object> row = baseRow();
        row.put("detail", "{\"pid\":123,\"ppid\":456}");

        EventResponse r = EventResponse.fromRow(row, mapper);

        assertEquals("host-1", r.host());
        assertEquals("process", r.type());
        assertEquals("chrome.exe", r.process());
        assertEquals("{\"pid\":123,\"ppid\":456}", r.detail());
        assertEquals(123, r.pid());
        assertEquals(456, r.ppid());
    }

    @Test
    void ts_가_문자열로_와도_숫자로_파싱한다() {
        Map<String, Object> row = baseRow();
        row.put("ts", "1700000000000");

        EventResponse r = EventResponse.fromRow(row, mapper);

        assertEquals(1700000000000L, r.ts());
    }

    @Test
    void ts_가_숫자로_와도_그대로_파싱한다() {
        Map<String, Object> row = baseRow();
        row.put("ts", 1700000000000L);

        EventResponse r = EventResponse.fromRow(row, mapper);

        assertEquals(1700000000000L, r.ts());
    }

    @Test
    void detail_이_빈_문자열이어도_이벤트는_버려지지_않는다() {
        Map<String, Object> row = baseRow();
        row.put("detail", "");

        EventResponse r = EventResponse.fromRow(row, mapper);

        assertEquals("host-1", r.host());
        assertEquals("", r.detail());
        assertNull(r.pid());
    }

    @Test
    void detail_이_깨진_JSON_이어도_이벤트는_버려지지_않고_나머지_컬럼은_그대로다() {
        Map<String, Object> row = baseRow();
        row.put("detail", "{이건 JSON 이 아니다");

        EventResponse r = EventResponse.fromRow(row, mapper);

        assertEquals("host-1", r.host());
        assertEquals("chrome.exe", r.process());
        assertNull(r.pid());
    }

    @Test
    void dns_detail_의_answers_와_status_0_이_펴진다() {
        Map<String, Object> row = baseRow();
        row.put("type", "dns");
        row.put("detail", "{\"queryType\":\"A\",\"answers\":[\"1.2.3.4\"],\"status\":0}");

        EventResponse r = EventResponse.fromRow(row, mapper);

        // detail 원본 JSON 의 키(queryType/answers/status)는 그대로다. 최상위로 펼 때만
        // alert 의 트리아지 status 와 헷갈리지 않게 dns 접두어를 붙인다.
        assertEquals("A", r.dnsRecordType());
        assertEquals(List.of("1.2.3.4"), r.dnsAnswers());
        assertEquals(0, r.dnsResponseCode());
    }

    @Test
    void ingestedAt_은_UTC_기준_epoch_millis_로_변환된다() {
        Map<String, Object> row = baseRow();
        row.put("ingested_at", "2026-07-31 00:00:00");

        EventResponse r = EventResponse.fromRow(row, mapper);

        assertEquals(1785456000000L, r.ingestedAt());
    }

    @Test
    void ingestedAt_은_DateTime64_밀리초_정밀도도_파싱한다() {
        Map<String, Object> row = baseRow();
        row.put("ingested_at", "2026-07-31 00:00:00.123");

        EventResponse r = EventResponse.fromRow(row, mapper);

        assertEquals(1785456000123L, r.ingestedAt());
    }

    @Test
    void ingestedAt_이_깨져도_이벤트는_버려지지_않고_0이_아니라_null_이다() {
        Map<String, Object> row = baseRow();
        row.put("ingested_at", "이건 날짜가 아니다");

        EventResponse r = EventResponse.fromRow(row, mapper);

        assertEquals("host-1", r.host());
        assertNull(r.ingestedAt());
    }

    @Test
    void ingestedAt_이_빈_문자열이어도_이벤트는_버려지지_않고_0이_아니라_null_이다() {
        Map<String, Object> row = baseRow();
        row.put("ingested_at", "");

        EventResponse r = EventResponse.fromRow(row, mapper);

        assertEquals("host-1", r.host());
        assertNull(r.ingestedAt());
    }

    private static Map<String, Object> baseRow() {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("host", "host-1");
        row.put("type", "process");
        row.put("ts", 1700000000000L);
        row.put("process", "chrome.exe");
        row.put("parent", "explorer.exe");
        row.put("cmdline", "chrome.exe --foo");
        row.put("dest_ip", "");
        row.put("dest_port", 0);
        row.put("domain", "");
        row.put("detail", "");
        row.put("sha256", "");
        row.put("ingested_at", "2026-07-31 00:00:00");
        return row;
    }
}
