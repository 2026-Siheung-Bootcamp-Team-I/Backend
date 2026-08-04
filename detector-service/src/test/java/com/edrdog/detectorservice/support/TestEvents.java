package com.edrdog.detectorservice.support;

import com.edrdog.schema.Event;

/**
 * 테스트에서 이벤트 한 건을 만드는 헬퍼.
 *
 * <p>예전 {@code TestEvents.of(...)} 와 인자 순서를 맞춰 둔 이유는 기존 테스트의 읽는 맛을 유지하려는 것이고,
 * null 을 빈 문자열로 바꾸는 일을 한 곳에 모으려는 것이다(proto3 빌더는 null 을 받으면 NPE).
 * 운영 코드에서는 쓰지 않는다. 거기서는 채우는 필드만 빌더로 지정한다.
 */
public final class TestEvents {

    private TestEvents() {
    }

    public static Event of(String host, String type, long ts,
                           String process, String parent, String cmdline,
                           String destIp, int destPort,
                           String domain, String detail, String sha256, String tenantId) {
        return Event.newBuilder()
                .setHost(nz(host))
                .setType(nz(type))
                .setTs(ts)
                .setProcess(nz(process))
                .setParent(nz(parent))
                .setCmdline(nz(cmdline))
                .setDestIp(nz(destIp))
                .setDestPort(destPort)
                .setDomain(nz(domain))
                .setDetail(nz(detail))
                .setSha256(nz(sha256))
                .setTenantId(nz(tenantId))
                .build();
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
