package com.edrdog.apiservice.intelligence.topology;

import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 등록가능 도메인(eTLD+1) 추출 검증. 뒤에서 라벨 2개를 자르는 방식이 틀리는 케이스(co.kr, com.au)와
 * 도메인이 아닌 목적지(IP 등)를 그룹으로 만들지 않는지를 본다.
 */
class RegistrableDomainTest {

    @Test
    void 일반_서브도메인은_등록가능_도메인으로_묶인다() {
        assertEquals(Optional.of("example.com"), RegistrableDomain.of("api.example.com"));
        assertEquals(Optional.of("example.com"), RegistrableDomain.of("a.b.c.example.com"));
    }

    @Test
    void 등록가능_도메인_자기_자신은_그대로() {
        assertEquals(Optional.of("example.com"), RegistrableDomain.of("example.com"));
    }

    // 라벨 2개를 자르면 "co.kr"/"com.au" 라는 존재하지 않는 묶음이 생긴다. PSL 로만 맞출 수 있다.
    @Test
    void 다중_라벨_공개접미사도_PSL_로_정확히_자른다() {
        assertEquals(Optional.of("example.co.kr"), RegistrableDomain.of("api.example.co.kr"));
        assertEquals(Optional.of("example.co.kr"), RegistrableDomain.of("example.co.kr"));
        assertEquals(Optional.of("example.com.au"), RegistrableDomain.of("www.example.com.au"));
    }

    @Test
    void 대문자와_끝점은_정규화한다() {
        assertEquals(Optional.of("example.com"), RegistrableDomain.of("API.Example.COM"));
        assertEquals(Optional.of("example.com"), RegistrableDomain.of("api.example.com."));
    }

    @Test
    void IPv4_는_그룹이_없다() {
        assertTrue(RegistrableDomain.of("10.0.0.9").isEmpty());
        assertTrue(RegistrableDomain.of("203.0.113.7").isEmpty());
    }

    @Test
    void IPv6_는_그룹이_없다() {
        assertTrue(RegistrableDomain.of("2001:db8::1").isEmpty());
    }

    @Test
    void 공개접미사_자체나_단일라벨은_그룹이_없다() {
        assertTrue(RegistrableDomain.of("com").isEmpty());
        assertTrue(RegistrableDomain.of("co.kr").isEmpty());
        assertTrue(RegistrableDomain.of("localhost").isEmpty());
    }

    @Test
    void PSL_에_없는_접미사는_그룹이_없다() {
        // .internal 같은 사설 접미사는 등록가능 도메인을 알 수 없다. 지어내지 않고 개별 목적지로 둔다.
        assertTrue(RegistrableDomain.of("db.corp.internal").isEmpty());
    }

    @Test
    void 빈값이나_깨진_값은_예외없이_빈_결과() {
        assertTrue(RegistrableDomain.of(null).isEmpty());
        assertTrue(RegistrableDomain.of("").isEmpty());
        assertTrue(RegistrableDomain.of("   ").isEmpty());
        assertTrue(RegistrableDomain.of("..").isEmpty());
        assertTrue(RegistrableDomain.of("-").isEmpty());
    }
}
