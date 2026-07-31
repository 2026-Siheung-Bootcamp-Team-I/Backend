package com.edrdog.apiservice.alert;

import com.edrdog.apiservice.alert.web.SourceEvent;

import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

/**
 * 판정을 유발한 원본 이벤트를 events 행에서 고르는 순수 로직.
 *
 * <p><b>시각은 1차 기준이 아니다.</b> 실기기는 초당 십여 건씩 이벤트를 내므로 어떤 창을 잡아도 그 안에
 * 수백 건이 들어오고, 그중 시각이 가장 가까운 것을 고르는 건 제비뽑기다. 조사 화면에서 틀린 원인을
 * 확신에 차서 보여 주는 건 아무것도 안 보여 주는 것보다 나쁘다(sensor/l7.go 가 프로세스를 비워 두는 것과 같은 이유).
 * 그래서 알림이 들고 있는 판별자로 후보를 먼저 좁히고, 그 안에서만 시각으로 고른다.
 * 판별자가 있는데 맞는 후보가 없으면 시각으로 되돌아가지 않고 null 이다.
 *
 * <p>판별자는 확신이 강한 순서로 하나만 쓴다:
 * <ol>
 *   <li>{@code matched} 마지막 줄 — detector 가 남긴 트리거 이벤트 요약. type 에 더해 프로세스명·부모·경로까지 짚는다.
 *       detector 는 예외 없이 트리거를 마지막에 담는다(Rules.alertOf).</li>
 *   <li>{@code rule_id} — 룰마다 걸리는 이벤트 type 이 1:1 로 정해져 있다(detector Rules).</li>
 * </ol>
 * 둘 다 못 쓰면 null 이다. 시각만으로 고르지 않는다.
 *
 * <p>알림의 {@code domain}/{@code dest_ip} 는 <b>판별자로 쓰지 않는다.</b> R2(DOWNLOAD_AND_EXECUTE)는
 * 다운로드(network)와 실행(process)을 상관하는데 목적지는 다운로드 쪽에서, {@code ts} 는 실행 쪽에서 온다.
 * 목적지로 거르면 시각과 무관한 네트워크 이벤트를 원인으로 짚거나 후보가 0 이 된다.
 *
 * <p>{@code Rules.summary()} 형식에 기대는 건 깨지기 쉽다. 그래서 파싱 실패를 정상 경로로 다룬다
 * (형식이 바뀌면 원인 이벤트가 안 보이는 것으로 끝나야지, 엉뚱한 이벤트를 보여 주면 안 된다).
 */
public final class SourceEventMatcher {

    /**
     * 후보를 훑는 앞뒤 폭 5초. 원본 이벤트는 alert.ts 와 시각이 같은 게 정상이고, 이 창은 수집·재구성
     * 과정에서 시각이 흔들린 경우를 덮는 여유일 뿐이다. 판별자로 이미 좁힌 뒤라 넓혀도 위험하지는 않지만,
     * 같은 판별자를 만족하는 반복 실행(같은 프로세스가 반복해 뜨는 경우)에서 엉뚱한 회차를 고르지 않도록 좁게 둔다.
     */
    public static final long WINDOW_MS = 5000;

    /** 룰이 어떤 type 의 이벤트로 완성되는지(detector Rules). alert.ts 는 그 이벤트의 시각이다. */
    private static final Map<String, String> TYPE_BY_RULE = Map.of(
            "SUSPICIOUS_PROCESS_CHAIN", "process",
            "DOWNLOAD_AND_EXECUTE", "process",
            "SCRIPT_FROM_TEMP_PATH", "script",
            "FILE_IN_AUTORUN_PATH", "file");

    private SourceEventMatcher() {
    }

    /** alert(판정기록 행)를 유발한 원본 이벤트. 못 찾으면 null 이다(빈 껍데기를 만들지 않는다). */
    public static SourceEvent match(List<Map<String, Object>> events, Map<String, Object> alert) {
        Discriminator discriminator = discriminatorOf(alert);
        if (discriminator == null) {
            return null;   // 좁힐 방법이 없으면 시각으로 아무거나 고르지 않는다
        }
        long alertTs = asLong(alert.get("ts"));

        Map<String, Object> best = null;
        long bestDistance = Long.MAX_VALUE;
        for (Map<String, Object> row : events) {
            long ts = asLong(row.get("ts"));
            long distance = Math.abs(ts - alertTs);
            if (distance > WINDOW_MS || !discriminator.test().test(row)) {
                continue;
            }
            // 거리가 같으면 먼저 일어난 쪽(ts 가 작은 쪽)을 남긴다. 원인은 판정보다 앞선다.
            if (best == null || distance < bestDistance
                    || (distance == bestDistance && ts < asLong(best.get("ts")))) {
                best = row;
                bestDistance = distance;
            }
        }
        return best == null ? null : SourceEvent.fromRow(best, discriminator.basis());
    }

    /** 후보를 좁히는 조건과 그 근거. */
    private record Discriminator(Predicate<Map<String, Object>> test, String basis) {
    }

    /** 후보를 좁힐 조건. 좁힐 방법이 없으면 null. */
    private static Discriminator discriminatorOf(Map<String, Object> alert) {
        Predicate<Map<String, Object>> bySummary = fromSummary(lastMatched(alert));
        if (bySummary != null) {
            return new Discriminator(bySummary, SourceEvent.BY_SUMMARY);
        }
        String type = TYPE_BY_RULE.get(str(alert.get("rule_id")));
        if (type != null) {
            return new Discriminator(row -> type.equals(str(row.get("type"))), SourceEvent.BY_RULE_TYPE);
        }
        return null;
    }

    /**
     * detector Rules.summary 형식을 되짚어 트리거 이벤트를 짚는 조건을 만든다. 형식이 다르면 null 이라
     * 다음 판별자로 넘어간다(detector 가 요약 형식을 바꿔도 조용히 틀린 답을 내지는 않는다).
     */
    private static Predicate<Map<String, Object>> fromSummary(String summary) {
        if (summary == null) {
            return null;
        }
        if (summary.startsWith("network ")) {
            String target = summary.substring("network ".length());   // <ip>:<port>
            return row -> isType(row, "network")
                    && target.equals(str(row.get("dest_ip")) + ":" + str(row.get("dest_port")));
        }
        if (summary.startsWith("file ")) {
            String path = summary.substring("file ".length());
            return row -> isType(row, "file") && path.equals(str(row.get("cmdline")));
        }
        if (summary.startsWith("script ")) {
            String process = between(summary, "script ", " (");
            return process == null ? null : row -> isType(row, "script") && process.equals(str(row.get("process")));
        }
        if (summary.startsWith("process ")) {
            String process = between(summary, "process ", " (parent ");
            if (process == null) {
                return null;
            }
            String parent = parentOf(summary);
            Predicate<Map<String, Object>> test =
                    row -> isType(row, "process") && process.equals(str(row.get("process")));
            // 요약은 부모가 없던 이벤트도 "(parent null)" 로 굳는다. 그런 값으로 후보를 좁히면 전부 탈락한다.
            if (parent == null || parent.isEmpty() || "null".equals(parent)) {
                return test;
            }
            return test.and(row -> parent.equals(str(row.get("parent"))));
        }
        return null;
    }

    /** 판정 근거 중 마지막 줄. detector 는 판정을 완성시킨(= alert.ts 인) 이벤트를 마지막에 담는다. */
    private static String lastMatched(Map<String, Object> alert) {
        Object v = alert.get("matched");
        if (!(v instanceof List<?> list) || list.isEmpty()) {
            return null;
        }
        return String.valueOf(list.get(list.size() - 1));
    }

    /** open 뒤부터 처음 나오는 close 앞까지. 값이 비면 null. */
    private static String between(String s, String open, String close) {
        int from = open.length();
        int to = s.indexOf(close, from);
        return to <= from ? null : s.substring(from, to);
    }

    /** "process <name> (parent <parent>)" 의 부모. 부모 값에 괄호가 있을 수 있어 닫는 괄호는 뒤에서 찾는다. */
    private static String parentOf(String summary) {
        String open = " (parent ";
        int from = summary.indexOf(open);
        int to = summary.lastIndexOf(')');
        if (from < 0 || to <= from + open.length()) {
            return null;
        }
        return summary.substring(from + open.length(), to);
    }

    private static boolean isType(Map<String, Object> row, String type) {
        return type.equals(str(row.get("type")));
    }

    private static String str(Object v) {
        return v == null ? "" : String.valueOf(v);
    }

    private static long asLong(Object v) {
        if (v == null) {
            return 0L;
        }
        if (v instanceof Number n) {
            return n.longValue();
        }
        return Long.parseLong(String.valueOf(v));
    }
}
