package com.edrdog.apiservice.intelligence.correlate;

import com.edrdog.apiservice.event.EventResponse;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 테스트용 이벤트 생성 도우미.
 *
 * <p>EventResponse 를 생성자로 직접 만들지 않고 ClickHouse 행에서 만드는 이유: 운영에서 오는
 * 것이 그 행이고, detail(JSON 문자열)에서 answers 를 꺼내는 경로까지 같이 지나야 실제와 같다.
 */
final class TestEvents {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private TestEvents() {
    }

    static EventResponse dns(String host, long ts, String domain, String process, List<String> answers) {
        String detail = answers.isEmpty()
                ? "{\"queryType\":\"A\"}"
                : "{\"queryType\":\"A\",\"answers\":[" + quoted(answers) + "]}";
        return row(host, "dns", ts, process, "", domain, detail);
    }

    static EventResponse network(String host, long ts, String destIp, String process) {
        return row(host, "network", ts, process, destIp, "", "{\"protocol\":\"tcp\"}");
    }

    static EventResponse l7(String host, long ts, String destIp, String domain, String process) {
        return row(host, "l7", ts, process, destIp, domain, "{\"l7Protocol\":\"TLS\"}");
    }

    private static EventResponse row(String host, String type, long ts, String process,
                                     String destIp, String domain, String detail) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("host", host);
        row.put("type", type);
        row.put("ts", ts);
        row.put("process", process);
        row.put("parent", "");
        row.put("cmdline", "");
        row.put("dest_ip", destIp);
        row.put("dest_port", 443);
        row.put("domain", domain);
        row.put("detail", detail);
        row.put("sha256", "");
        row.put("ingested_at", "");
        return EventResponse.fromRow(row, MAPPER);
    }

    private static String quoted(List<String> values) {
        return values.stream().map(v -> "\"" + v + "\"").reduce((a, b) -> a + "," + b).orElse("");
    }
}
