package com.edrdog.apiservice.intelligence.correlate;

import com.edrdog.apiservice.web.EventResponse;
import org.junit.jupiter.api.Test;

import java.util.List;

import static com.edrdog.apiservice.intelligence.correlate.TestEvents.dns;
import static com.edrdog.apiservice.intelligence.correlate.TestEvents.network;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * macOS DNS 이벤트의 프로세스 보정(순수 매칭) 검증.
 *
 * 핵심은 두 가지다. 되짚어 찾은 값은 관측 자리에 들어가지 않아야 하고(추론 칸에만 담긴다),
 * 근거가 약하면 지어내지 말고 비워 둬야 한다(에이전트가 mDNSResponder 를 안 채운 것과 같은 원칙).
 */
class DnsProcessBackfillTest {

    private static final long T = 1_700_000_000_000L;

    @Test
    void 프로세스가_빈_DNS_는_응답_IP_로_붙은_직후_이벤트에서_질의자를_되짚는다() {
        EventResponse d = dns("mac-1", T, "example.com", "", List.of("93.184.216.34"));
        EventResponse n = network("mac-1", T + 120, "93.184.216.34", "/Applications/Firefox.app/firefox");

        List<CorrelatedEvent> out = DnsProcessBackfill.apply(List.of(d), List.of(n));

        assertEquals(1, out.size());
        assertEquals("/Applications/Firefox.app/firefox", out.get(0).inferredProcess());
        assertTrue(out.get(0).inferenceBasis().contains("93.184.216.34"), out.get(0).inferenceBasis());
        // 관측 자리는 그대로 비어 있어야 한다. 추론이 관측을 덮으면 구분이 사라진다.
        assertEquals("", out.get(0).event().process());
    }

    @Test
    void l7_이벤트도_질의자_후보다() {
        EventResponse d = dns("mac-1", T, "example.com", "", List.of("93.184.216.34"));
        EventResponse l7 = TestEvents.l7("mac-1", T + 50, "93.184.216.34", "example.com", "/usr/bin/curl");

        List<CorrelatedEvent> out = DnsProcessBackfill.apply(List.of(d), List.of(l7));

        assertEquals("/usr/bin/curl", out.get(0).inferredProcess());
    }

    @Test
    void 프로세스가_이미_있으면_보정하지_않는다() {
        // Windows(ETW)는 정상적으로 채워져 온다. 관측값이 있으면 추론이 끼어들 자리가 없다.
        EventResponse d = dns("win-1", T, "example.com", "chrome.exe", List.of("93.184.216.34"));
        EventResponse n = network("win-1", T + 100, "93.184.216.34", "svchost.exe");

        List<CorrelatedEvent> out = DnsProcessBackfill.apply(List.of(d), List.of(n));

        assertNull(out.get(0).inferredProcess());
        assertEquals("chrome.exe", out.get(0).event().process());
    }

    @Test
    void 다른_호스트의_접속은_질의자가_아니다() {
        EventResponse d = dns("mac-1", T, "example.com", "", List.of("93.184.216.34"));
        EventResponse n = network("mac-2", T + 100, "93.184.216.34", "firefox");

        assertNull(DnsProcessBackfill.apply(List.of(d), List.of(n)).get(0).inferredProcess());
    }

    @Test
    void 응답_IP_와_목적지가_다르면_질의자가_아니다() {
        EventResponse d = dns("mac-1", T, "example.com", "", List.of("93.184.216.34"));
        EventResponse n = network("mac-1", T + 100, "1.1.1.1", "firefox");

        assertNull(DnsProcessBackfill.apply(List.of(d), List.of(n)).get(0).inferredProcess());
    }

    @Test
    void 창_밖의_접속은_질의자가_아니다() {
        // 한참 뒤의 접속은 그 질의 때문이라고 볼 근거가 없다(캐시된 IP 로 나중에 붙었을 수도 있다).
        EventResponse d = dns("mac-1", T, "example.com", "", List.of("93.184.216.34"));
        EventResponse tooLate = network("mac-1", T + DnsProcessBackfill.WINDOW_MS + 1, "93.184.216.34", "firefox");
        EventResponse tooEarly = network("mac-1", T - DnsProcessBackfill.TOLERANCE_MS - 1, "93.184.216.34", "firefox");

        assertNull(DnsProcessBackfill.apply(List.of(d), List.of(tooLate, tooEarly)).get(0).inferredProcess());
    }

    @Test
    void 질의보다_아주_조금_앞선_접속은_허용한다() {
        // 같은 에이전트가 찍은 두 이벤트라 시계는 같지만 밀리초 단위 순서가 뒤집힐 수 있다.
        EventResponse d = dns("mac-1", T, "example.com", "", List.of("93.184.216.34"));
        EventResponse n = network("mac-1", T - 200, "93.184.216.34", "firefox");

        assertEquals("firefox", DnsProcessBackfill.apply(List.of(d), List.of(n)).get(0).inferredProcess());
    }

    @Test
    void 후보가_여럿이면_질의에_가장_가까운_접속을_고른다() {
        EventResponse d = dns("mac-1", T, "example.com", "", List.of("93.184.216.34"));
        EventResponse far = network("mac-1", T + 9_000, "93.184.216.34", "curl");
        EventResponse near = network("mac-1", T + 30, "93.184.216.34", "firefox");

        assertEquals("firefox", DnsProcessBackfill.apply(List.of(d), List.of(far, near)).get(0).inferredProcess());
    }

    @Test
    void 프로세스가_빈_후보는_질의자로_쓰지_않는다() {
        EventResponse d = dns("mac-1", T, "example.com", "", List.of("93.184.216.34"));
        EventResponse blank = network("mac-1", T + 10, "93.184.216.34", "");
        EventResponse named = network("mac-1", T + 500, "93.184.216.34", "firefox");

        assertEquals("firefox", DnsProcessBackfill.apply(List.of(d), List.of(blank, named)).get(0).inferredProcess());
    }

    @Test
    void 응답_IP_가_없는_DNS_는_되짚을_실마리가_없다() {
        // NXDOMAIN 이면 answers 가 비어 온다. 이때 아무 접속이나 갖다 붙이면 그건 지어내는 것이다.
        EventResponse d = dns("mac-1", T, "nx.example.com", "", List.of());
        EventResponse n = network("mac-1", T + 10, "93.184.216.34", "firefox");

        assertNull(DnsProcessBackfill.apply(List.of(d), List.of(n)).get(0).inferredProcess());
    }

    @Test
    void DNS_가_아닌_이벤트는_손대지_않는다() {
        EventResponse n = network("mac-1", T, "93.184.216.34", "firefox");

        List<CorrelatedEvent> out = DnsProcessBackfill.apply(List.of(n), List.of(n));

        assertEquals(1, out.size());
        assertNull(out.get(0).inferredProcess());
    }

    @Test
    void 후보가_아예_없어도_이벤트는_그대로_돌려준다() {
        EventResponse d = dns("mac-1", T, "example.com", "", List.of("93.184.216.34"));

        List<CorrelatedEvent> out = DnsProcessBackfill.apply(List.of(d), List.of());

        assertEquals(1, out.size());
        assertNull(out.get(0).inferredProcess());
    }
}
