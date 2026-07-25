package com.edrdog.collectorservice;

import com.edrdog.collectorservice.dto.Event;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Optional;

/**
 * osquery 원시 result-log JSON 1건을 정규화된 Event 로 변환하는 순수 매핑.
 *
 * <p>osquery 는 소비자 스키마에 맞추지 않고 자기 표준 포맷(차등 result-log)으로만 로그를 낸다.
 * 실제 컬럼 값은 {@code columns} 안에 중첩되고 {@code hostIdentifier}/{@code unixTime}/{@code action}
 * 같은 래핑 필드가 항상 붙는다. 이 매핑이 그 껍데기를 벗기고 detector 스키마로 정규화한다.
 *
 * <p>변환 규칙:
 * <ul>
 *   <li>host   = 래핑 {@code hostIdentifier} (구버전 {@code hostname} 폴백)</li>
 *   <li>ts     = 래핑 {@code unixTime}(초) × 1000 (없으면 columns.time 폴백)</li>
 *   <li>type   = 쿼리명({@code name}) 매칭: socket/network→network, file→file, script→script, 그 외 process</li>
 *   <li>process= columns.path(file 은 target_path) 의 basename (구분자 {@code /}, {@code \} 모두 처리)</li>
 *   <li>parent = columns.parent (osquery.conf 쿼리에서 processes 조인으로 이름을 넣어 둠)</li>
 *   <li>cmdline= columns.cmdline. file 이벤트는 판정용 전체 경로(target_path)를 담는다.</li>
 *   <li>destIp/destPort = columns.remote_address / remote_port</li>
 * </ul>
 *
 * <p>차등 로그의 top-level {@code action} 이 {@code removed}(프로세스 종료 등)면 스킵한다.
 * columns 가 없거나 JSON 이 깨졌으면 예외 없이 스킵한다.
 */
public final class RawEventMapper {

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
        if ("removed".equals(text(root, "action"))) {
            return Optional.empty();   // 프로세스 종료 등 생성이 아닌 이벤트
        }
        JsonNode columns = root.get("columns");
        if (columns == null || !columns.isObject()) {
            return Optional.empty();
        }

        String host = firstNonBlank(text(root, "hostIdentifier"), text(root, "hostname"));
        long ts = toMillis(firstNonBlank(text(root, "unixTime"), text(columns, "time")));
        String type = classify(text(root, "name"));
        String tenantId = text(root, "tenantId");   // 수집 API 가 node_key→tenant 로 풀어 루트에 태깅

        if (Event.TYPE_NETWORK.equals(type)) {
            return Optional.of(new Event(
                    host, type, ts, basename(text(columns, "path")), null,
                    text(columns, "cmdline"),
                    text(columns, "remote_address"),
                    toInt(text(columns, "remote_port")),
                    tenantId));
        }
        if (Event.TYPE_FILE.equals(type)) {
            // FIM: target_path 전체를 판정용으로 cmdline 에 싣고, basename 을 파일명으로.
            String path = firstNonBlank(text(columns, "target_path"), text(columns, "path"));
            return Optional.of(new Event(
                    host, type, ts, basename(path), null,
                    path, null, 0, tenantId));
        }
        // process / script: 동일한 프로세스 컬럼 구조. script 는 cmdline 에 스크립트 경로가 포함됨.
        return Optional.of(new Event(
                host, type, ts, basename(text(columns, "path")),
                text(columns, "parent"),
                text(columns, "cmdline"),
                null, 0,
                tenantId));
    }

    /** 쿼리명으로 이벤트 타입 판정. socket/network→network, file→file, script→script, 그 외 process. */
    private static String classify(String name) {
        if (name == null) {
            return Event.TYPE_PROCESS;
        }
        String n = name.toLowerCase();
        if (n.contains("socket") || n.contains("network")) {
            return Event.TYPE_NETWORK;
        }
        if (n.contains("file")) {
            return Event.TYPE_FILE;
        }
        if (n.contains("script")) {
            return Event.TYPE_SCRIPT;
        }
        return Event.TYPE_PROCESS;
    }

    /** 경로에서 파일명만 추출. {@code /} 와 {@code \} 를 모두 구분자로 본다. */
    private static String basename(String path) {
        if (path == null || path.isEmpty()) {
            return path;
        }
        int cut = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\'));
        return cut < 0 ? path : path.substring(cut + 1);
    }

    private static long toMillis(String unixSeconds) {
        if (unixSeconds == null || unixSeconds.isBlank()) {
            return 0L;
        }
        try {
            return Long.parseLong(unixSeconds.trim()) * 1000L;
        } catch (NumberFormatException e) {
            return 0L;
        }
    }

    private static int toInt(String s) {
        if (s == null || s.isBlank()) {
            return 0;
        }
        try {
            return Integer.parseInt(s.trim());
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static String text(JsonNode node, String field) {
        JsonNode v = node.get(field);
        return v == null || v.isNull() ? null : v.asText();
    }

    private static String firstNonBlank(String a, String b) {
        return a != null && !a.isBlank() ? a : b;
    }
}
