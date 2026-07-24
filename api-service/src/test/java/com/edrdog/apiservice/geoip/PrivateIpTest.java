package com.edrdog.apiservice.geoip;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 공인/사설/garbage IP 판별 순수 로직 검증.
 */
class PrivateIpTest {

    // --- 공인 ---

    @Test
    void 공인_IPv4는_true() {
        assertTrue(PrivateIp.isPublic("8.8.8.8"));
        assertTrue(PrivateIp.isPublic("1.1.1.1"));
        assertTrue(PrivateIp.isPublic("203.0.113.7"));
    }

    @Test
    void 공인_IPv6는_true() {
        assertTrue(PrivateIp.isPublic("2001:4860:4860::8888"));
    }

    @Test
    void 앞뒤_공백은_무시() {
        assertTrue(PrivateIp.isPublic("  8.8.8.8 "));
    }

    // --- 사설/특수 ---

    @Test
    void loopback은_false() {
        assertFalse(PrivateIp.isPublic("127.0.0.1"));
        assertFalse(PrivateIp.isPublic("::1"));
    }

    @Test
    void private_IPv4_대역은_false() {
        assertFalse(PrivateIp.isPublic("10.0.0.5"));
        assertFalse(PrivateIp.isPublic("172.16.0.1"));
        assertFalse(PrivateIp.isPublic("172.31.255.255"));
        assertFalse(PrivateIp.isPublic("192.168.1.1"));
    }

    @Test
    void link_local은_false() {
        assertFalse(PrivateIp.isPublic("169.254.1.1"));
        assertFalse(PrivateIp.isPublic("fe80::1"));
    }

    @Test
    void IPv6_ULA는_false() {
        assertFalse(PrivateIp.isPublic("fc00::1"));
        assertFalse(PrivateIp.isPublic("fd12:3456::1"));
    }

    @Test
    void 경계값_172_15와_172_32는_공인() {
        assertTrue(PrivateIp.isPublic("172.15.0.1"));
        assertTrue(PrivateIp.isPublic("172.32.0.1"));
    }

    // --- garbage / null ---

    @Test
    void null_blank는_false() {
        assertFalse(PrivateIp.isPublic(null));
        assertFalse(PrivateIp.isPublic(""));
        assertFalse(PrivateIp.isPublic("   "));
    }

    @Test
    void 파싱불가_문자열은_false() {
        assertFalse(PrivateIp.isPublic("notanip"));
        assertFalse(PrivateIp.isPublic("garbage"));
        assertFalse(PrivateIp.isPublic("example.com"));
    }
}
