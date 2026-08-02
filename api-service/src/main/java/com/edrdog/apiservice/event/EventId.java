package com.edrdog.apiservice.event;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;

/**
 * 이벤트의 결정적 id 생성(순수). 이벤트 자체의 값을 UUID v3(name-based)로 접어 만든다(AlertId 와 같은 방식).
 *
 * <p>씨앗은 host|ts|type|process|pid|parent|dest_ip|dest_port 다. 조회 경로마다 뽑는 컬럼이 달라
 * 모든 경로에 있는 것만 남긴 결과라, 하나라도 더하거나 빼면 같은 이벤트가 경로마다 다른 id 를 받는다.
 *
 * <p>host 는 SELECT 하지 않는 경로가 있어 인자로 받는다. 필수로 둬야 새 조회 경로가 빠뜨릴 때
 * 조용히 다른 id 가 나오는 대신 컴파일이 깨진다.
 */
public final class EventId {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private EventId() {
    }

    public static String of(String host, long ts, String type, String process, Integer pid,
                            String parent, String destIp, Integer destPort) {
        // dest_port 는 events 조회가 0, 타임라인이 null 로 "없음" 을 표현한다. 같은 것으로 접는다.
        String seed = text(host) + "|" + ts + "|" + text(type) + "|" + text(process)
                + "|" + (pid == null ? "" : pid) + "|" + text(parent) + "|" + text(destIp)
                + "|" + (destPort == null ? 0 : destPort);
        return UUID.nameUUIDFromBytes(seed.getBytes(StandardCharsets.UTF_8)).toString();
    }

    /** ClickHouse events 행에서 바로 만든다. pid 는 detail(JSON) 안에 있어 여기서 꺼낸다. */
    public static String ofRow(String host, Map<String, Object> row) {
        EventDetail detail = EventDetail.parse(text(row.get("detail")), MAPPER);
        return of(host, asLong(row.get("ts")), text(row.get("type")), text(row.get("process")), detail.pid(),
                text(row.get("parent")), text(row.get("dest_ip")), asInt(row.get("dest_port")));
    }

    private static String text(Object v) {
        return v == null ? "" : String.valueOf(v);
    }

    /** ClickHouse UInt64 는 JSON 에서 문자열로 온다(EventResponse.asLong 과 같은 이유). */
    private static long asLong(Object v) {
        if (v == null) {
            return 0L;
        }
        if (v instanceof Number n) {
            return n.longValue();
        }
        return Long.parseLong(String.valueOf(v));
    }

    private static Integer asInt(Object v) {
        if (v == null) {
            return null;
        }
        if (v instanceof Number n) {
            return n.intValue();
        }
        return Integer.parseInt(String.valueOf(v));
    }
}
