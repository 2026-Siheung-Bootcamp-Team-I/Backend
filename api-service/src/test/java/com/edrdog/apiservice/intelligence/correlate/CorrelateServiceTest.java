package com.edrdog.apiservice.intelligence.correlate;

import com.edrdog.apiservice.clickhouse.ClickHouseHttp;
import com.edrdog.apiservice.clickhouse.ClickHouseReader;
import com.edrdog.apiservice.query.ClickHouseQuery;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 조회 -> 보정 -> 실시간 조회를 엮는 순서 검증. 실시간 DNS 는 외부 의존이라 대역으로 갈아 끼운다.
 *
 * 특히 확인하는 것: DNS 조회가 실패해도 관측 데이터는 그대로 나가야 한다. 조회 하나 때문에
 * 화면 전체가 안 뜨면 안 된다.
 */
class CorrelateServiceTest {

    private static final long T = 1_700_000_000_000L;
    private static final CorrelateTarget DOMAIN = new CorrelateTarget(TargetKind.DOMAIN, "example.com");
    private static final CorrelateTarget IP = new CorrelateTarget(TargetKind.IP, "93.184.216.34");

    @Test
    void DNS_조회가_실패해도_관측_관계는_그대로_나간다() {
        FakeReader reader = new FakeReader(List.of(dnsRow("win-1", T, "example.com", "chrome.exe", "93.184.216.34")));
        CorrelateService service = service(reader, failingResolver());

        CorrelateResponse res = service.correlate("1", DOMAIN, null, null, null, true);

        assertEquals(1, res.observedEvents());
        assertTrue(res.edges().stream().anyMatch(e -> e.origin() == RelationOrigin.OBSERVED));
        assertEquals(LookupStatus.FAILED, res.liveDns().forward().status());
        assertFalse(res.edges().stream().anyMatch(e -> e.origin() == RelationOrigin.LIVE_DNS));
    }

    @Test
    void liveDns_를_끄면_외부에_묻지_않는다() {
        CountingResolver resolver = new CountingResolver();
        CorrelateService service = service(new FakeReader(List.of()), resolver);

        CorrelateResponse res = service.correlate("1", DOMAIN, null, null, null, false);

        assertNull(res.liveDns());
        assertEquals(0, resolver.calls);
    }

    @Test
    void 프로세스가_빈_DNS_가_없으면_보정_조회를_보내지_않는다() {
        // Windows 만 있는 조직은 이 경로를 안 탄다. 쓸데없는 질의를 한 번 더 보내지 않는다.
        FakeReader reader = new FakeReader(List.of(dnsRow("win-1", T, "example.com", "chrome.exe", "93.184.216.34")));
        service(reader, new CountingResolver()).correlate("1", DOMAIN, null, null, null, false);

        assertEquals(1, reader.queries.size());
    }

    @Test
    void 프로세스가_빈_DNS_는_두_번째_조회로_질의자를_되짚는다() {
        FakeReader reader = new FakeReader(
                List.of(dnsRow("mac-1", T, "example.com", "", "93.184.216.34")),
                List.of(connectRow("mac-1", T + 100, "93.184.216.34", "firefox")));
        CorrelateResponse res = service(reader, new CountingResolver())
                .correlate("1", DOMAIN, null, null, null, false);

        assertEquals(2, reader.queries.size());
        CorrelationEdge inferred = res.edges().stream()
                .filter(e -> e.origin() == RelationOrigin.INFERRED).findFirst()
                .orElseThrow(() -> new AssertionError("추론 엣지 없음: " + res.edges()));
        assertEquals("process:firefox", inferred.from());
    }

    @Test
    void 모든_조회에_tenant_가_실린다() {
        FakeReader reader = new FakeReader(
                List.of(dnsRow("mac-1", T, "example.com", "", "93.184.216.34")),
                List.of(connectRow("mac-1", T + 100, "93.184.216.34", "firefox")));
        service(reader, new CountingResolver()).correlate("42", DOMAIN, null, null, null, false);

        assertEquals(2, reader.queries.size());
        reader.queries.forEach(q -> assertEquals("42", q.params().get("tenant"), q.sql()));
    }

    @Test
    void IP_대상은_역방향만_묻는다() {
        DnsLookupResponse res = service(new FakeReader(List.of()), okResolver()).lookup(IP);

        assertNull(res.forward());
        assertEquals(List.of("ptr.example.com"), res.reverse().ptrNames());
    }

    @Test
    void 도메인_대상은_정방향만_묻는다() {
        DnsLookupResponse res = service(new FakeReader(List.of()), okResolver()).lookup(DOMAIN);

        assertNull(res.reverse());
        assertEquals(List.of("1.2.3.4"), res.forward().addresses());
    }

    // --- 대역 ---

    private static CorrelateService service(ClickHouseReader reader, DnsResolver resolver) {
        return new CorrelateService(reader, new CorrelateQueryBuilder("edrdog.events"), resolver, new ObjectMapper());
    }

    private static DnsResolver failingResolver() {
        return new DnsResolver() {
            @Override
            public ForwardLookup forward(String domain) {
                return ForwardLookup.failed("timeout");
            }

            @Override
            public ReverseLookup reverse(String ip) {
                return ReverseLookup.failed("timeout");
            }
        };
    }

    private static DnsResolver okResolver() {
        return new DnsResolver() {
            @Override
            public ForwardLookup forward(String domain) {
                return ForwardLookup.ok(List.of("1.2.3.4"));
            }

            @Override
            public ReverseLookup reverse(String ip) {
                return ReverseLookup.ok(List.of("ptr.example.com"));
            }
        };
    }

    private static final class CountingResolver implements DnsResolver {

        private int calls;

        @Override
        public ForwardLookup forward(String domain) {
            calls++;
            return ForwardLookup.notFound();
        }

        @Override
        public ReverseLookup reverse(String ip) {
            calls++;
            return ReverseLookup.notFound();
        }
    }

    /** ClickHouse 대신 미리 준비한 행을 순서대로 돌려준다. 실제 HTTP 는 일어나지 않는다. */
    private static final class FakeReader extends ClickHouseReader {

        private final List<List<Map<String, Object>>> responses;
        private final List<ClickHouseQuery> queries = new ArrayList<>();

        @SafeVarargs
        FakeReader(List<Map<String, Object>>... responses) {
            super(new ClickHouseHttp("http://localhost:8123", "edrdog", "u", "p", 1000, 1000), new ObjectMapper());
            this.responses = List.of(responses);
        }

        @Override
        public List<Map<String, Object>> query(ClickHouseQuery q) {
            queries.add(q);
            int i = queries.size() - 1;
            return i < responses.size() ? responses.get(i) : List.of();
        }
    }

    private static Map<String, Object> dnsRow(String host, long ts, String domain, String process, String answer) {
        Map<String, Object> row = baseRow(host, "dns", ts, process);
        row.put("domain", domain);
        row.put("detail", "{\"queryType\":\"A\",\"answers\":[\"" + answer + "\"]}");
        return row;
    }

    private static Map<String, Object> connectRow(String host, long ts, String destIp, String process) {
        Map<String, Object> row = baseRow(host, "network", ts, process);
        row.put("dest_ip", destIp);
        return row;
    }

    private static Map<String, Object> baseRow(String host, String type, long ts, String process) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("host", host);
        row.put("type", type);
        row.put("ts", ts);
        row.put("process", process);
        row.put("parent", "");
        row.put("cmdline", "");
        row.put("dest_ip", "");
        row.put("dest_port", 0);
        row.put("domain", "");
        row.put("detail", "{}");
        row.put("sha256", "");
        row.put("ingested_at", "");
        return row;
    }
}
