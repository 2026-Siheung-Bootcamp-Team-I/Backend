package com.edrdog.collectorservice;

import com.edrdog.collectorservice.dto.Event;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Optional;

/**
 * 에이전트가 보낸 이벤트 JSON 1건을 검증해 {@link Event} 로 통과시키는 검증 경계.
 *
 * <p>이전에는 osquery 원시 result-log 의 {@code columns} 중첩과 {@code hostIdentifier}/{@code unixTime}
 * 같은 래퍼를 벗기는 변환이 필요했다. 이제 에이전트가 detector 스키마 그대로(평평한 JSON) 보내므로
 * 벗길 껍데기가 없다. 그래도 이 서비스를 없애지는 않는다. 엔드포인트에서 들어온 입력을 detector 에
 * 넘기기 전에 거르는 검증 경계로 남긴다. 망가진 이벤트가 detector 까지 흘러가면 판정이 오염된다.
 *
 * <p>검증 규칙:
 * <ul>
 *   <li>JSON 이 깨졌거나 객체가 아니면 스킵</li>
 *   <li>{@code host} 가 비었으면 스킵 (상관분석 키가 없으면 쓸모가 없다)</li>
 *   <li>{@code type} 이 process/network/file/script/dns/l7 이 아니면 스킵 (모르는 타입을 process 로 넘겨짚지 않는다)</li>
 *   <li>{@code ts} 가 없거나 0 이하면 스킵</li>
 *   <li>{@code ts} 가 초 단위로 보이면 스킵. epoch millis 라야 한다.</li>
 *   <li>{@code network} 인데 {@code destIp} 가 비었으면 스킵</li>
 *   <li>{@code dns}/{@code l7} 인데 {@code domain} 이 비었으면 스킵. 도메인이 없으면 어느 이름을 물어봤는지
 *       모르니 남겨도 조사에 쓸 수 없다(network 가 destIp 없으면 버리는 것과 같은 이유다)</li>
 * </ul>
 *
 * <p>그 외에는 값을 그대로 옮긴다. basename 추출, 타입 추측, 시각 변환 같은 변환은 하지 않는다.
 * 이제 그 일은 에이전트가 한다(경로 구분자가 플랫폼마다 다르니 그 플랫폼에서 도는 쪽이 판단하는 게 맞다).
 */
public final class RawEventMapper {

    /**
     * ts 가 이 값보다 작으면 초 단위를 밀리초로 착각해 보낸 것으로 본다.
     * 100_000_000_000L 을 밀리초로 보면 1973년 근방이라, 현실적인 이벤트 시각이 이보다 작을 수 없다.
     */
    private static final long MIN_PLAUSIBLE_MILLIS = 100_000_000_000L;

    private RawEventMapper() {
    }

    public static Optional<Event> map(String rawJson, ObjectMapper mapper) {
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
