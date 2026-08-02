package com.edrdog.apiservice.event;

import com.edrdog.apiservice.alert.web.SourceEvent;
import com.edrdog.apiservice.incident.web.IncidentTimelineResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * 이벤트 id 의 결정성 검증. 이 id 로 화면이 "알림의 원본 이벤트" 와 "타임라인의 그 줄" 이
 * 같은 것임을 알기 때문에, 세 응답에서 같은 값이 나오는지와 조회 경로별 컬럼 차이에
 * 흔들리지 않는지가 핵심이다.
 */
class EventIdTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void 같은_이벤트는_세_응답에서_같은_id_다() {
        Map<String, Object> row = baseRow();

        String fromEvents = EventResponse.fromRow(row, mapper).id();
        String fromAlert = SourceEvent.fromRow(row, SourceEvent.BY_SUMMARY).id();
        String fromTimeline = timeline("host-1", row).entries().get(0).eventId();

        assertEquals(fromEvents, fromAlert);
        assertEquals(fromEvents, fromTimeline);
    }

    /** 동일 이미지를 대량 배포한 환경에서는 여러 기기가 같은 이벤트를 같은 시각에 낸다. */
    @Test
    void 내용과_시각과_pid_가_같아도_host_가_다르면_다른_id_다() {
        Map<String, Object> other = baseRow();
        other.put("host", "host-2");

        assertNotEquals(EventResponse.fromRow(baseRow(), mapper).id(), EventResponse.fromRow(other, mapper).id());
        assertNotEquals(timeline("host-1", baseRow()).entries().get(0).eventId(),
                timeline("host-2", baseRow()).entries().get(0).eventId());
    }

    @Test
    void 같은_행을_다시_읽어도_같은_id_다() {
        Map<String, Object> row = baseRow();

        assertEquals(EventResponse.fromRow(row, mapper).id(), EventResponse.fromRow(baseRow(), mapper).id());
    }

    @Test
    void 시각이_다르면_다른_id_다() {
        Map<String, Object> other = baseRow();
        other.put("ts", 1700000000001L);

        assertNotEquals(EventResponse.fromRow(baseRow(), mapper).id(), EventResponse.fromRow(other, mapper).id());
    }

    @Test
    void 같은_시각_같은_프로세스라도_pid_가_다르면_다른_id_다() {
        Map<String, Object> other = baseRow();
        other.put("detail", "{\"pid\":999}");

        assertNotEquals(EventResponse.fromRow(baseRow(), mapper).id(), EventResponse.fromRow(other, mapper).id());
    }

    @Test
    void 목적지가_다르면_다른_id_다() {
        Map<String, Object> other = baseRow();
        other.put("dest_ip", "10.0.0.9");

        assertNotEquals(EventResponse.fromRow(baseRow(), mapper).id(), EventResponse.fromRow(other, mapper).id());
    }

    /**
     * lineageEvents 는 host/cmdline/domain/sha256/ingested_at 을 뽑지 않는다. 그 컬럼들이 씨앗에
     * 들어가 있으면 같은 이벤트가 조회 경로에 따라 다른 id 를 받는다.
     */
    @Test
    void 조회_경로마다_없는_컬럼은_id_를_바꾸지_않는다() {
        Map<String, Object> lineageRow = new LinkedHashMap<>();
        lineageRow.put("type", "network");
        lineageRow.put("ts", 1700000000000L);
        lineageRow.put("process", "chrome.exe");
        lineageRow.put("parent", "explorer.exe");
        lineageRow.put("dest_ip", "1.1.1.1");
        lineageRow.put("dest_port", 443);
        lineageRow.put("detail", "{\"pid\":123}");

        assertEquals(EventResponse.fromRow(baseRow(), mapper).id(), EventId.ofRow("host-1", lineageRow));
    }

    /** ClickHouse UInt64 는 JSON 에서 문자열로 오므로 같은 값이면 표기가 달라도 같은 id 여야 한다. */
    @Test
    void ts_가_문자열로_와도_같은_id_다() {
        Map<String, Object> asText = baseRow();
        asText.put("ts", "1700000000000");

        assertEquals(EventResponse.fromRow(baseRow(), mapper).id(), EventResponse.fromRow(asText, mapper).id());
    }

    /** 타임라인은 dest_port 가 없는 이벤트를 null 로, events 조회는 0 으로 준다. 같은 "없음" 이다. */
    @Test
    void 포트가_없으면_null_과_0_이_같은_id_다() {
        assertEquals(EventId.of("host-1", 1700000000000L, "process", "chrome.exe", 123, "explorer.exe", "", 0),
                EventId.of("host-1", 1700000000000L, "process", "chrome.exe", 123, "explorer.exe", "", null));
    }

    /** 알림 줄은 이벤트가 아니라 alertId 로 짚는다. 이벤트 id 를 만들어 붙이면 없는 이벤트를 가리킨다. */
    @Test
    void 타임라인의_알림_줄에는_이벤트_id_가_없다() {
        IncidentTimelineResponse.Entry alert = new IncidentTimelineResponse.Entry(
                1700000000000L, "alert", null, "chrome.exe", null, null, null, null, null, "evil.com",
                "alert-1", "rule-1", "위협", "high");

        IncidentTimelineResponse timeline = new IncidentTimelineResponse("inc-1", "host-1", List.of(alert));

        assertNull(timeline.entries().get(0).eventId());
    }

    private static Map<String, Object> baseRow() {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("host", "host-1");
        row.put("type", "network");
        row.put("ts", 1700000000000L);
        row.put("process", "chrome.exe");
        row.put("parent", "explorer.exe");
        row.put("cmdline", "chrome.exe --headless");
        row.put("dest_ip", "1.1.1.1");
        row.put("dest_port", 443);
        row.put("domain", "example.com");
        row.put("detail", "{\"pid\":123}");
        row.put("sha256", "abc");
        row.put("ingested_at", "2023-11-14 22:13:20.000");
        return row;
    }

    /** IncidentService 가 타임라인 이벤트 줄을 만들어 응답으로 감싸는 방식 그대로. */
    private IncidentTimelineResponse timeline(String host, Map<String, Object> row) {
        EventDetail detail = EventDetail.parse(String.valueOf(row.get("detail")), mapper);
        IncidentTimelineResponse.Entry entry = new IncidentTimelineResponse.Entry(
                Long.parseLong(String.valueOf(row.get("ts"))), "event", String.valueOf(row.get("type")),
                String.valueOf(row.get("process")), detail.pid(), String.valueOf(row.get("parent")),
                String.valueOf(row.get("cmdline")), String.valueOf(row.get("dest_ip")),
                (Integer) row.get("dest_port"), String.valueOf(row.get("domain")),
                null, null, null, null);
        return new IncidentTimelineResponse("inc-1", host, List.of(entry));
    }
}
