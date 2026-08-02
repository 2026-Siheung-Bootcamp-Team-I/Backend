package com.edrdog.apiservice.event;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

/**
 * GET /api/events 응답 한 건. detail(JSON 문자열) 안의 값을 named 필드로 펴서 준다.
 *
 * detail 원본 문자열도 같이 남긴다. 빼면 named 목록에 없는 키가 늘 때마다 API 를 고쳐야 한다.
 *
 * dns 필드는 detail 의 queryType/answers/status 에 dns 접두어를 붙인 이름이다. 최상위에서는 status 만으로
 * DNS 응답 코드인지 알 수 없고 alert 트리아지 status 와도 겹친다. detail 원본 JSON 키는 에이전트와의 계약이라 바꾸지 않는다.
 *
 * id 는 저장된 값이 아니라 이벤트 내용에서 접어 만든 것이라(EventId), 알림 상세·타임라인과 같은 값이 나와야 화면이 셋을 잇는다.
 */
public record EventResponse(
        String id,
        String host,
        String type,
        long ts,
        String process,
        String parent,
        String cmdline,
        String destIp,
        int destPort,
        String domain,
        String sha256,
        Long ingestedAt,
        String detail,
        Integer pid,
        Integer ppid,
        String protocol,
        String action,
        String dnsRecordType,
        List<String> dnsAnswers,
        Integer dnsResponseCode,
        String tlsVersion,
        List<String> alpn,
        String l7Protocol,
        String httpMethod,
        String httpPath,
        String httpUserAgent,
        Integer httpStatusCode
) {
    public static EventResponse fromRow(Map<String, Object> row, ObjectMapper mapper) {
        String rawDetail = str(row, "detail");
        EventDetail d = EventDetail.parse(rawDetail, mapper);
        long ts = asLong(row, "ts");
        return new EventResponse(
                EventId.of(str(row, "host"), ts, str(row, "type"), str(row, "process"), d.pid(),
                        str(row, "parent"), str(row, "dest_ip"), asInt(row, "dest_port")),
                str(row, "host"), str(row, "type"), ts, str(row, "process"), str(row, "parent"),
                str(row, "cmdline"), str(row, "dest_ip"), asInt(row, "dest_port"), str(row, "domain"),
                str(row, "sha256"), parseIngestedAt(str(row, "ingested_at")), rawDetail,
                d.pid(), d.ppid(), d.protocol(), d.action(), d.queryType(), d.answers(), d.status(),
                d.tlsVersion(), d.alpn(), d.l7Protocol(), d.httpMethod(), d.httpPath(), d.httpUserAgent(),
                d.httpStatusCode());
    }

    private static String str(Map<String, Object> row, String key) {
        Object v = row.get(key);
        return v == null ? "" : String.valueOf(v);
    }

    /** ClickHouse UInt64 는 JSON 에서 문자열로 오므로 문자열/숫자 모두 받는다. */
    private static long asLong(Map<String, Object> row, String key) {
        Object v = row.get(key);
        if (v == null) {
            return 0L;
        }
        if (v instanceof Number n) {
            return n.longValue();
        }
        return Long.parseLong(String.valueOf(v));
    }

    private static int asInt(Map<String, Object> row, String key) {
        Object v = row.get(key);
        if (v == null) {
            return 0;
        }
        if (v instanceof Number n) {
            return n.intValue();
        }
        return Integer.parseInt(String.valueOf(v));
    }

    /**
     * ClickHouse DateTime64(3) 를 epoch millis 로 바꾼다. ClickHouse 가 timezone 표기 없이 UTC 로 주므로 UTC 로 고정 해석한다.
     * 파싱 실패는 0 이 아니라 null 이다. 0 을 주면 "읽지 못했다" 가 화면에 1970년으로 보인다.
     */
    private static Long parseIngestedAt(String s) {
        if (s == null || s.isBlank()) {
            return null;
        }
        try {
            return LocalDateTime.parse(s.trim().replace(' ', 'T')).toInstant(ZoneOffset.UTC).toEpochMilli();
        } catch (Exception e) {
            return null;
        }
    }
}
