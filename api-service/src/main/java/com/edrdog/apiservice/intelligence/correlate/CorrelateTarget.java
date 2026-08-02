package com.edrdog.apiservice.intelligence.correlate;

import com.google.common.net.InetAddresses;
import com.google.common.net.InternetDomainName;

import java.util.Locale;

/**
 * 사용자가 준 조회 대상 문자열을 검증해 도메인/IP 로 가른 것.
 * 형식 검증을 빼면 사용자 문자열이 그대로 외부 DNS 질의에 실린다.
 * 정규화는 에이전트의 normalizeDNSName 과 같게 맞춘다. 다르면 관측된 domain 과 안 맞아 "관측된 적 없음"으로 보인다.
 */
public record CorrelateTarget(TargetKind kind, String value) {

    public static CorrelateTarget parse(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new IllegalArgumentException("조회 대상(도메인 또는 IP)이 필요합니다");
        }
        String v = raw.trim();

        // IP 를 먼저 본다. 숫자만으로 된 문자열은 도메인 문법으로도 통과할 수 있어서다.
        if (InetAddresses.isInetAddress(v)) {
            // 에이전트는 Go net.IP.String() 으로 적재하므로 소문자 축약형이다. 같은 모양으로 맞춘다.
            return new CorrelateTarget(TargetKind.IP, InetAddresses.toAddrString(InetAddresses.forString(v)));
        }

        String domain = v.toLowerCase(Locale.ROOT);
        while (domain.endsWith(".")) {
            domain = domain.substring(0, domain.length() - 1);
        }
        if (domain.isEmpty() || !InternetDomainName.isValid(domain)) {
            throw new IllegalArgumentException("도메인 또는 IP 형식이 아닙니다: " + raw);
        }
        return new CorrelateTarget(TargetKind.DOMAIN, domain);
    }
}
