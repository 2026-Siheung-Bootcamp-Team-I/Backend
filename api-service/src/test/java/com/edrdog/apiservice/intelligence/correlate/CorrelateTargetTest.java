package com.edrdog.apiservice.intelligence.correlate;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 조회 대상 문자열 검증·정규화의 순수 로직 검증.
 * 이 값은 그대로 외부 DNS 질의에 실리므로 형식이 아닌 문자열은 반드시 막혀야 하고,
 * 관측 데이터와 맞물리려면 에이전트의 정규화(소문자, 후행 점 제거)와 같은 모양이어야 한다.
 */
class CorrelateTargetTest {

    @Test
    void 도메인을_도메인으로_가른다() {
        CorrelateTarget t = CorrelateTarget.parse("example.com");
        assertEquals(TargetKind.DOMAIN, t.kind());
        assertEquals("example.com", t.value());
    }

    @Test
    void 도메인은_소문자와_후행점_제거로_정규화한다() {
        // 에이전트의 normalizeDNSName 과 같은 모양이어야 관측된 domain 컬럼과 맞는다.
        assertEquals("example.com", CorrelateTarget.parse("  Example.COM.  ").value());
    }

    @Test
    void 서브도메인도_그대로_받는다() {
        assertEquals("a.b.example.co.kr", CorrelateTarget.parse("a.b.example.co.kr").value());
    }

    @Test
    void IPv4_를_IP_로_가른다() {
        CorrelateTarget t = CorrelateTarget.parse("93.184.216.34");
        assertEquals(TargetKind.IP, t.kind());
        assertEquals("93.184.216.34", t.value());
    }

    @Test
    void IPv6_는_에이전트와_같은_축약형으로_정규화한다() {
        // 에이전트는 Go net.IP.String() 으로 적재하므로 소문자 축약형이다. 대문자로 들어와도 맞아야 한다.
        assertEquals("2001:db8::1", CorrelateTarget.parse("2001:0DB8:0000:0000:0000:0000:0000:0001").value());
    }

    @Test
    void 빈_값은_거부한다() {
        assertThrows(IllegalArgumentException.class, () -> CorrelateTarget.parse(null));
        assertThrows(IllegalArgumentException.class, () -> CorrelateTarget.parse("   "));
    }

    @Test
    void 도메인도_IP_도_아니면_거부한다() {
        assertThrows(IllegalArgumentException.class, () -> CorrelateTarget.parse("not a domain"));
        assertThrows(IllegalArgumentException.class, () -> CorrelateTarget.parse("http://example.com"));
        assertThrows(IllegalArgumentException.class, () -> CorrelateTarget.parse("example.com/../evil"));
        assertThrows(IllegalArgumentException.class, () -> CorrelateTarget.parse("exa mple.com"));
    }

    @Test
    void 질의에_섞일_수_있는_문자는_거부한다() {
        // 사용자 문자열이 그대로 DNS 질의로 나가므로 이름 문법에 없는 문자는 여기서 끊는다.
        assertThrows(IllegalArgumentException.class, () -> CorrelateTarget.parse("example.com;ls"));
        assertThrows(IllegalArgumentException.class, () -> CorrelateTarget.parse("exam\nple.com"));
        assertThrows(IllegalArgumentException.class, () -> CorrelateTarget.parse("*.example.com"));
    }
}
