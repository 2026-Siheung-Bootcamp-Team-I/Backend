package com.edrdog.apiservice.host;

import com.edrdog.apiservice.alert.HostAlertCount;
import com.edrdog.apiservice.host.web.HostResponse;
import com.edrdog.apiservice.host.web.HostSummary;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * events 행과 alert 집계를 host 기준으로 병합하는 순수 로직 검증.
 * 호스트 집합은 events 기준, status/위협수는 alert 집계에서 붙는다.
 */
class HostAggregatorTest {

    /** ClickHouse 응답 한 행(host, last_seen). last_seen 은 UInt64 라 문자열로 온다. */
    private static Map<String, Object> row(String host, String lastSeen) {
        return Map.of("host", host, "last_seen", lastSeen);
    }

    /** HostAlertCount projection 테스트용 구현. */
    private static HostAlertCount count(String host, long total, long critical, long high) {
        return new HostAlertCount() {
            public String getHost() {
                return host;
            }

            public long getOpenTotal() {
                return total;
            }

            public long getOpenCritical() {
                return critical;
            }

            public long getOpenHigh() {
                return high;
            }
        };
    }

    @Test
    void alert_없는_host_는_정상_위협0() {
        List<HostResponse> hosts = HostAggregator.hosts(
                List.of(row("h1", "1000")), List.of());

        assertEquals(1, hosts.size());
        HostResponse h = hosts.get(0);
        assertEquals("h1", h.host());
        assertEquals(1000L, h.lastSeen());
        assertEquals(HostStatus.HEALTHY, h.status());
        assertEquals(0L, h.threats());
    }

    @Test
    void 열린_CRITICAL_있는_host_는_위험_위협수는_열린총수() {
        List<HostResponse> hosts = HostAggregator.hosts(
                List.of(row("h1", "1000")),
                List.of(count("h1", 3, 1, 2)));

        HostResponse h = hosts.get(0);
        assertEquals(HostStatus.CRITICAL, h.status());
        assertEquals(3L, h.threats());
    }

    @Test
    void HIGH만_있는_host_는_주의() {
        List<HostResponse> hosts = HostAggregator.hosts(
                List.of(row("h1", "1000")),
                List.of(count("h1", 2, 0, 2)));

        assertEquals(HostStatus.WARNING, hosts.get(0).status());
        assertEquals(2L, hosts.get(0).threats());
    }

    @Test
    void events_순서를_그대로_유지한다() {
        List<HostResponse> hosts = HostAggregator.hosts(
                List.of(row("h2", "3000"), row("h1", "1000")),
                List.of(count("h1", 1, 1, 0)));

        assertEquals("h2", hosts.get(0).host());
        assertEquals("h1", hosts.get(1).host());
    }

    @Test
    void alert만_있고_events_없는_host_는_목록에_없다() {
        List<HostResponse> hosts = HostAggregator.hosts(
                List.of(row("h1", "1000")),
                List.of(count("ghost", 5, 5, 0)));

        assertEquals(1, hosts.size());
        assertEquals("h1", hosts.get(0).host());
    }

    @Test
    void 요약은_status별_수와_총수를_센다() {
        List<HostResponse> hosts = List.of(
                new HostResponse("h1", 1, HostStatus.CRITICAL, 2),
                new HostResponse("h2", 1, HostStatus.WARNING, 1),
                new HostResponse("h3", 1, HostStatus.HEALTHY, 0),
                new HostResponse("h4", 1, HostStatus.HEALTHY, 0));

        HostSummary s = HostAggregator.summary(hosts);
        assertEquals(2L, s.healthy());
        assertEquals(1L, s.warning());
        assertEquals(1L, s.critical());
        assertEquals(4L, s.total());
    }

    @Test
    void 빈_목록_요약은_전부_0() {
        HostSummary s = HostAggregator.summary(List.of());
        assertEquals(0L, s.healthy());
        assertEquals(0L, s.warning());
        assertEquals(0L, s.critical());
        assertEquals(0L, s.total());
    }
}
