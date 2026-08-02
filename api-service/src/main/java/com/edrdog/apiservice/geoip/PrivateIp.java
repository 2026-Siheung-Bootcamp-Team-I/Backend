package com.edrdog.apiservice.geoip;

import java.net.InetAddress;

/**
 * IP 가 "공인(라우팅 가능한)" 주소인지 판별하는 순수 로직. geo 매핑 대상만 통과시키는 데 쓴다.
 * 판정이 느슨해지면 사설 IP 가 지도에 뜨고, 빡빡해지면 공인 IP 가 지도에서 빠진다.
 */
public final class PrivateIp {

    private PrivateIp() {
    }

    /** null/blank/파싱불가/사설/loopback/link-local/ULA 는 false, 그 외 공인 IP 는 true. */
    public static boolean isPublic(String ip) {
        if (ip == null) {
            return false;
        }
        String s = ip.trim();
        if (s.isEmpty() || !looksNumeric(s)) {
            return false;
        }
        InetAddress addr;
        try {
            addr = InetAddress.getByName(s);
        } catch (Exception e) {
            return false;
        }
        if (addr.isLoopbackAddress() || addr.isLinkLocalAddress() || addr.isSiteLocalAddress()
                || addr.isAnyLocalAddress() || addr.isMulticastAddress()) {
            return false;
        }
        byte[] b = addr.getAddress();
        if (b.length == 4) {
            // isSiteLocalAddress 가 대부분 잡지만, 172.16.0.0/12 를 놓치면 사설 IP 가 지도에 뜬다.
            int o0 = b[0] & 0xff;
            int o1 = b[1] & 0xff;
            if (o0 == 172 && o1 >= 16 && o1 <= 31) {
                return false;
            }
        } else {
            // IPv6 ULA fc00::/7 -> 첫 바이트 0xfc 또는 0xfd
            int f = b[0] & 0xff;
            if (f == 0xfc || f == 0xfd) {
                return false;
            }
        }
        return true;
    }

    /** 숫자 IP 리터럴 형태만 통과. 호스트명이 새면 InetAddress.getByName 이 DNS 조회를 나간다. */
    private static boolean looksNumeric(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean ok = (c >= '0' && c <= '9')
                    || (c >= 'a' && c <= 'f')
                    || (c >= 'A' && c <= 'F')
                    || c == '.' || c == ':' || c == '%';
            if (!ok) {
                return false;
            }
        }
        return true;
    }
}
