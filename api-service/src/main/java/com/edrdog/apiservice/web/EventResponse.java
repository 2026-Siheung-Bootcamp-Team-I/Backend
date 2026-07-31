package com.edrdog.apiservice.web;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

/**
 * GET /api/events 응답 한 건. ClickHouse 행을 그대로 던지던 것을 걷어내고, detail(JSON 문자열)
 * 안의 값을 named 필드로 편다. 프론트가 더 이상 JSON.parse(detail) 을 직접 할 필요가 없다.
 *
 * detail 원본 문자열도 남겨 둔다. 아래 named 필드 목록에 없는 키가 나중에 늘어도
 * (예: 인증서 필드) 조사 화면에서 원본으로 볼 수 있어야 API 를 매번 안 고쳐도 된다.
 *
 * dns 관련 필드는 detail 안에서는 queryType/answers/status 지만, 여기서는 dnsRecordType/
 * dnsAnswers/dnsResponseCode 로 접두어를 붙인다. 평평하게 펴진 최상위 자리에서는 status 만으로
 * "DNS 응답 코드"인지 알 수 없고, 이 API 에는 alert 트리아지 status 라는 다른 개념도 있어서다.
 * detail 원본 JSON 의 키는 에이전트와의 계약이라 바꾸지 않는다(EventDetail 참고).
 *
 * id 는 저장된 값이 아니라 이벤트 내용에서 접어 만든 것이다(EventId). 알림 상세의 원본 이벤트,
 * 사건 타임라인의 이벤트 줄과 같은 값이 나오므로 화면이 셋을 같은 이벤트로 이을 수 있다.
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

    /** ClickHouse UInt64 는 JSON 에서 문자열로 오므로 문자열/숫자 모두 안전하게 파싱한다(AlertResponse.asLong 과 같은 이유). */
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
     * ClickHouse DateTime64(3) 를 epoch millis 로 바꾼다. ClickHouse 는 이 값을 timezone 표기 없이
     * UTC 로 저장/반환하므로 여기서도 UTC 로 고정 해석한다. ts/lastSeen 등 이 API 의 다른 시각
     * 필드가 전부 epoch millis 라서 여기만 문자열로 두면 프론트가 필드마다 다르게 파싱해야 한다.
     *
     * 비어 있거나 형식이 깨지면 0 이 아니라 null 을 준다. ts 는 없으면 그 행이 이상한 것이지만
     * ingested_at 파싱 실패는 "값이 없다" 가 아니라 "읽지 못했다" 이고, 0 을 주면 1970년으로
     * 보여 pid 를 못 읽었을 때 null 로 두는 이 DTO 의 다른 필드와 "모름" 표현이 갈린다.
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
