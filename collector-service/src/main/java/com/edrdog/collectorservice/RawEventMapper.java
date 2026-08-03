package com.edrdog.collectorservice;

import com.edrdog.collectorservice.dto.Event;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * 에이전트가 보낸 이벤트 JSON 1건을 검증해 {@link Event} 로 통과시키는 검증 경계.
 * 에이전트가 평평한 JSON 을 보내 변환할 것은 없지만, 망가진 이벤트가 흘러가면 판정이 오염돼 거르는 경계로 남긴다.
 * 값은 그대로 옮기며 basename 추출·타입 추측·시각 변환 같은 일은 하지 않는다.
 */
public final class RawEventMapper {

    /** ts 가 이 값보다 작으면 초 단위를 밀리초로 착각해 보낸 값이다. 밀리초로 보면 1973년 근방이라 정상 이벤트가 이보다 작을 수 없다. */
    private static final long MIN_PLAUSIBLE_MILLIS = 100_000_000_000L;

    /**
     * 서버 시각보다 이만큼 넘게 앞선 ts 는 단말 시계가 틀어진 것으로 보고 서버 시각으로 당긴다.
     * 그냥 두면 detector 의 워터마크가 그 값까지 튀어 다른 이벤트의 상관 버퍼가 통째로 날아간다.
     * 버리지 않고 당기는 이유는 시계가 틀어진 단말의 이벤트도 판정에는 써야 하기 때문이다.
     */
    private static final long MAX_CLOCK_SKEW_MILLIS = 60_000L;

    /** SHA-256 은 32바이트라 16진수 표기로 정확히 64자리다. 길이가 다르면 다른 알고리즘이거나 잘린 값이다. */
    private static final Pattern SHA256_PATTERN = Pattern.compile("[0-9a-fA-F]{64}");

    private RawEventMapper() {
    }

    public static Optional<Event> map(String rawJson, ObjectMapper mapper) {
        return map(rawJson, mapper, System.currentTimeMillis());
    }

    /** 시각 보정 기준을 주입받는 형태 (테스트용). */
    public static Optional<Event> map(String rawJson, ObjectMapper mapper, long nowMillis) {
        JsonNode root;
        try {
            root = mapper.readTree(rawJson);
        } catch (Exception e) {
            return Optional.empty();   // 깨진 JSON 은 유실보다 스킵
        }
        if (root == null || !root.isObject()) {
            return Optional.empty();
        }

        String host = text(root, "host");
        if (host == null || host.isBlank()) {
            return Optional.empty();
        }

        String type = text(root, "type");
        if (!isKnownType(type)) {
            return Optional.empty();
        }

        Long ts = longValue(root, "ts");
        if (ts == null || ts <= 0) {
            return Optional.empty();
        }
        if (ts < MIN_PLAUSIBLE_MILLIS) {
            return Optional.empty();   // 초 단위로 잘못 보낸 값
        }
        // 앞선 시계 보정
        if (ts > nowMillis + MAX_CLOCK_SKEW_MILLIS) {
            ts = nowMillis;
        }

        String destIp = text(root, "destIp");
        if (Event.TYPE_NETWORK.equals(type) && (destIp == null || destIp.isBlank())) {
            return Optional.empty();
        }

        String domain = text(root, "domain");
        if (needsDomain(type) && (domain == null || domain.isBlank())) {
            return Optional.empty();
        }

        return Optional.of(new Event(
                host,
                type,
                ts,
                text(root, "process"),
                text(root, "parent"),
                text(root, "cmdline"),
                destIp,
                intValue(root, "destPort"),
                domain,
                text(root, "detail"),
                normalizeSha256(text(root, "sha256")),
                text(root, "tenantId")));
    }

    private static boolean isKnownType(String type) {
        return Event.TYPE_PROCESS.equals(type)
                || Event.TYPE_NETWORK.equals(type)
                || Event.TYPE_FILE.equals(type)
                || Event.TYPE_SCRIPT.equals(type)
                || Event.TYPE_DNS.equals(type)
                || Event.TYPE_L7.equals(type);
    }

    /** dns/l7 은 도메인이 핵심 값이다. 그게 없으면 남겨도 조사에 쓸 수 없어 버린다. */
    private static boolean needsDomain(String type) {
        return Event.TYPE_DNS.equals(type) || Event.TYPE_L7.equals(type);
    }

    /** 같은 해시가 대소문자 때문에 둘로 보이면 조회가 갈린다. 64자리 16진수가 아니면 null 로 떨어뜨린다(이벤트는 살린다). */
    private static String normalizeSha256(String raw) {
        if (raw == null) {
            return null;
        }
        String trimmed = raw.trim();
        return SHA256_PATTERN.matcher(trimmed).matches() ? trimmed.toLowerCase(Locale.ROOT) : null;
    }

    private static String text(JsonNode node, String field) {
        JsonNode v = node.get(field);
        return v == null || v.isNull() ? null : v.asText();
    }

    private static Long longValue(JsonNode node, String field) {
        JsonNode v = node.get(field);
        if (v == null || v.isNull()) {
            return null;
        }
        if (v.isNumber()) {
            return v.asLong();
        }
        if (v.isTextual()) {
            try {
                return Long.parseLong(v.asText().trim());
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }

    private static int intValue(JsonNode node, String field) {
        JsonNode v = node.get(field);
        if (v == null || v.isNull()) {
            return 0;
        }
        if (v.isNumber()) {
            return v.asInt();
        }
        if (v.isTextual()) {
            try {
                return Integer.parseInt(v.asText().trim());
            } catch (NumberFormatException e) {
                return 0;
            }
        }
        return 0;
    }
}
