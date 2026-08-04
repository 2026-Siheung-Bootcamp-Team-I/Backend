package com.edrdog.schema;

import org.apache.kafka.common.header.Headers;
import java.nio.charset.StandardCharsets;

/**
 * events 레코드에 싣는 메타데이터 헤더.
 *
 * <p>본문이 바이너리라 kafbat UI 에서 눈으로 읽을 수 없다. 헤더는 그 자리를 메우는 짝이고,
 * 전송량을 줄이지는 않는다. 본문을 풀지 않고도 어느 스키마 버전인지, 어떤 이벤트인지,
 * 어느 조직 것인지는 알 수 있어야 한다.
 */
public final class EventHeaders {

    /** 스키마 버전. 필드를 늘려 호환이 갈라질 때 어느 규칙으로 읽을지 판단하는 근거다. */
    public static final String SCHEMA_VERSION = "schema-version";

    /** 본문을 풀지 않고 이벤트 종류로 거를 때 쓴다. */
    public static final String EVENT_TYPE = "event-type";

    /** 본문을 풀지 않고 조직으로 거를 때 쓴다. */
    public static final String TENANT_ID = "tenant-id";

    /** 현재 스키마 버전. event.proto 를 호환 깨지게 바꾸면 올린다. */
    public static final String CURRENT_SCHEMA_VERSION = "1";

    private EventHeaders() {
    }

    /** 발행 직전 레코드에 헤더를 심는다. 값이 빈 필드는 싣지 않는다(없는 값을 빈 문자열로 남기지 않는다). */
    public static void stamp(Headers headers, Event event) {
        put(headers, SCHEMA_VERSION, CURRENT_SCHEMA_VERSION);
        put(headers, EVENT_TYPE, event.getType());
        put(headers, TENANT_ID, event.getTenantId());
    }

    private static void put(Headers headers, String key, String value) {
        if (value != null && !value.isEmpty()) {
            headers.add(key, value.getBytes(StandardCharsets.UTF_8));
        }
    }
}
