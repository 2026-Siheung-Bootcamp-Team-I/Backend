package com.edrdog.detectorservice.rule;

import com.edrdog.detectorservice.dto.Alert;
import com.edrdog.detectorservice.dto.Event;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * 시퀀스 상관분석 룰 판정 (순수 로직). 버퍼(prior)는 프로세서가 윈도우로 정리한 뒤 넘겨준다.
 * 각 룰은 버퍼의 선행 이벤트 + 현재 이벤트를 상관하여 판정한다.
 */
public final class Rules {

    private Rules() {
    }

    /** office 계열 앱 — 이 앱이 shell 을 자식으로 띄우면 매크로/문서 기반 침투 의심. */
    private static final Set<String> OFFICE_APPS = Set.of(
            "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe");

    /** 인터프리터/스크립트 shell — office 자식으로 뜨면 위험. */
    private static final Set<String> SHELLS = Set.of(
            "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe");

    /** 다운로드로 간주하는 목적지 포트 (HTTP/HTTPS 계열). */
    private static final Set<Integer> DOWNLOAD_PORTS = Set.of(80, 443, 8080);

    /** baseline: 알려진 정상 프로세스 — 룰에 걸려도 오탐이므로 억제. */
    private static final Set<String> BASELINE_SAFE = Set.of(
            "onedrive.exe", "teams.exe", "gupdate.exe", "msedgeupdate.exe", "update.exe");

    /** 자동실행/시작 경로 표식 (Windows) — 여기에 파일이 생기면 지속성 확보 의심(R4). 소문자 기준. */
    private static final Set<String> FILE_AUTORUN_MARKERS = Set.of(
            "\\startup\\", "\\currentversion\\run");

    /** 현재 이벤트가 선행 버퍼와 상관되어 룰을 완성하면 Alert 반환. 여러 룰 매칭 시 가장 심각한 것 채택. */
    public static Optional<Alert> evaluate(List<Event> prior, Event current) {
        if (current == null || current.host() == null) {
            return Optional.empty();
        }
        // 시도 순서가 곧 우선순위다. 순서를 바꾸면 CRITICAL 이 될 이벤트가 낮은 심각도로 덮인다.
        Optional<Alert> r2 = downloadAndExecute(prior, current);
        if (r2.isPresent()) {
            return r2;
        }
        Optional<Alert> r1 = suspiciousProcessChain(prior, current);
        if (r1.isPresent()) {
            return r1;
        }
        // 저심각 단일-이벤트(point) 룰 — 시퀀스 상관 없이 현재 이벤트만으로 판정
        Optional<Alert> r3 = scriptFromTempPath(current);
        if (r3.isPresent()) {
            return r3;
        }
        return fileInAutorunPath(current);
    }

    /**
     * 선행 이벤트로 버퍼에 남길 가치가 있는지 (순수 판정).
     * 전부 담으면 버퍼 상한이 금방 차서 5분 윈도우가 십여 초로 줄고 상관 룰이 발화하지 못한다.
     */
    public static boolean isCorrelatable(Event e) {
        if (e == null) {
            return false;
        }
        if (isNetwork(e)) {
            return DOWNLOAD_PORTS.contains(e.destPort());
        }
        if (isProcess(e)) {
            return in(OFFICE_APPS, lower(e.process()))
                    || executableFromTempPath(e.cmdline());
        }
        return false;
    }

    /** R1 T1059: 버퍼의 office앱 exec → 그 office앱을 부모로 shell 실행. */
    private static Optional<Alert> suspiciousProcessChain(List<Event> prior, Event current) {
        if (!isProcess(current)) {
            return Optional.empty();
        }
        String child = lower(current.process());
        String parent = lower(current.parent());
        if (!in(SHELLS, child) || !in(OFFICE_APPS, parent) || isBaseline(child)) {
            return Optional.empty();
        }
        // 시퀀스: 그 office앱(부모)의 exec 이벤트가 버퍼에 선행해야 함
        Optional<Event> officeExec = prior.stream()
                .filter(Rules::isProcess)
                .filter(e -> parent.equals(lower(e.process())))
                .findFirst();
        if (officeExec.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(alertOf("SUSPICIOUS_PROCESS_CHAIN", "T1059", Alert.SEV_HIGH,
                current, List.of(officeExec.get())));
    }

    /**
     * R2 T1105+T1204: network 다운로드 → 이후 process 실행.
     * 판정은 이벤트 시각 순서로 한다. 도착 순서로 보면 이 조합을 거의 놓친다.
     */
    private static Optional<Alert> downloadAndExecute(List<Event> prior, Event current) {
        // 네트워크가 늦게 도착한 경우: 버퍼에서 그 뒤에 실행된 프로세스를 찾는다.
        if (isNetwork(current) && DOWNLOAD_PORTS.contains(current.destPort())) {
            return prior.stream()
                    .filter(Rules::isProcess)
                    .filter(e -> !isBaseline(lower(e.process())))
                    .filter(e -> executableFromTempPath(e.cmdline()))
                    .filter(e -> e.ts() >= current.ts())   // 시각상 다운로드가 먼저여야 한다
                    .findFirst()
                    .map(exec -> alertOf("DOWNLOAD_AND_EXECUTE", "T1105+T1204", Alert.SEV_CRITICAL,
                            exec, List.of(current)));
        }
        if (!isProcess(current) || isBaseline(lower(current.process()))) {
            return Optional.empty();
        }
        // 이 검사가 없으면 웹 접속 한 번 뒤의 모든 프로세스 실행이 CRITICAL 이 된다.
        if (!executableFromTempPath(current.cmdline())) {
            return Optional.empty();
        }
        Optional<Event> download = prior.stream()
                .filter(Rules::isNetwork)
                .filter(e -> DOWNLOAD_PORTS.contains(e.destPort()))
                .filter(e -> e.ts() <= current.ts())   // 시각상 다운로드가 먼저여야 한다
                .findFirst();
        if (download.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(alertOf("DOWNLOAD_AND_EXECUTE", "T1105+T1204", Alert.SEV_CRITICAL,
                current, List.of(download.get())));
    }

    /** R3 T1059: 임시/다운로드 경로에서 실행된 스크립트 (저심각 point 룰). */
    private static Optional<Alert> scriptFromTempPath(Event current) {
        if (!isScript(current) || !pathArgumentFromTempPath(current.cmdline())) {
            return Optional.empty();
        }
        return Optional.of(alertOf("SCRIPT_FROM_TEMP_PATH", "T1059", Alert.SEV_MEDIUM,
                current, List.of()));
    }

    /** R4 T1547: 자동실행/시작 경로에 생성된 파일 (지속성 확보, 저심각 point 룰). */
    private static Optional<Alert> fileInAutorunPath(Event current) {
        if (!isFile(current) || !isAutorunPath(current.cmdline())) {
            return Optional.empty();
        }
        return Optional.of(alertOf("FILE_IN_AUTORUN_PATH", "T1547", Alert.SEV_MEDIUM,
                current, List.of()));
    }

    /** 판정 결과 조립. matched 의 마지막은 항상 트리거다. 순서를 바꾸면 api-service 가 원본 이벤트를 되찾지 못한다. */
    private static Alert alertOf(String ruleId, String mitre, String severity, Event trigger, List<Event> prior) {
        List<Event> evidence = new ArrayList<>(prior);
        evidence.add(trigger);
        Event destination = destinationOf(evidence);
        return new Alert(
                trigger.host(),
                ruleId,
                mitre,
                severity,
                Alert.actionFor(severity),
                trigger.ts(),
                evidence.stream().map(Rules::summary).toList(),
                trigger.tenantId(),
                actTarget(trigger),
                destination == null ? "" : nz(destination.domain()),
                destination == null ? "" : nz(destination.destIp()));
    }

    /** 근거 중 목적지를 관측한 이벤트 (없으면 null). 트리거만 보면 도착 순서에 따라 목적지가 빈다. */
    private static Event destinationOf(List<Event> evidence) {
        return evidence.stream()
                .filter(e -> !nz(e.destIp()).isBlank() || !nz(e.domain()).isBlank())
                .findFirst()
                .orElse(null);
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }

    private static boolean isProcess(Event e) {
        return Event.TYPE_PROCESS.equals(e.type());
    }

    private static boolean isNetwork(Event e) {
        return Event.TYPE_NETWORK.equals(e.type());
    }

    private static boolean isScript(Event e) {
        return Event.TYPE_SCRIPT.equals(e.type());
    }

    private static boolean isFile(Event e) {
        return Event.TYPE_FILE.equals(e.type());
    }

    /** 셸 연산자 — 여기부터는 실행 대상이 아니라 출력/후속 명령이라 판정에서 제외한다. */
    private static final Set<String> SHELL_OPERATORS = Set.of(">", ">>", ">|", "<", "|", "||", "&&", ";", "&");

    /** 실행된 파일 자체(argv[0])만 본다. 인자까지 보면 임시 경로를 인자로 받는 정상 프로세스가 오탐된다. */
    private static boolean executableFromTempPath(String cmdline) {
        String c = lower(cmdline);
        if (c == null) {
            return false;
        }
        List<String> tokens = tokenize(c);
        return !tokens.isEmpty() && isTempOrDownloadPath(tokens.get(0));
    }

    /** cmdline 에서 "실행 대상으로 보이는 경로 인자"가 임시·다운로드 경로인지 본다. */
    private static boolean pathArgumentFromTempPath(String cmdline) {
        String c = lower(cmdline);
        if (c == null) {
            return false;
        }
        for (String token : tokenize(c)) {
            if (SHELL_OPERATORS.contains(token)) {
                return false;   // 여기서 안 끊으면 리다이렉션 대상(>| /tmp/x)이 임시 경로라고 알림이 나간다
            }
            if (isTempOrDownloadPath(token)) {
                return true;
            }
        }
        return false;
    }

    /** 공백으로 자르되 인용부호 구간은 한 토큰으로 유지한다. 공백으로만 자르면 공백 포함 경로를 아예 못 본다. */
    private static List<String> tokenize(String cmdline) {
        List<String> tokens = new ArrayList<>();
        StringBuilder token = new StringBuilder();
        char quote = 0;
        for (char ch : cmdline.toCharArray()) {
            if (quote != 0) {
                if (ch == quote) {
                    quote = 0;
                } else {
                    token.append(ch);
                }
            } else if (ch == '"' || ch == '\'') {
                quote = ch;
            } else if (Character.isWhitespace(ch)) {
                if (token.length() > 0) {
                    tokens.add(token.toString());
                    token.setLength(0);
                }
            } else {
                token.append(ch);
            }
        }
        if (token.length() > 0) {
            tokens.add(token.toString());
        }
        return tokens;
    }

    /** 시스템 임시·다운로드 경로인지 (소문자 기준). 조각 검색으로 바꾸면 앱 내부 tmp 폴더가 오탐된다. */
    private static boolean isTempOrDownloadPath(String p) {
        if (p.startsWith("/")) {
            return p.startsWith("/tmp/")
                    || p.startsWith("/private/tmp/")
                    || p.startsWith("/var/folders/")
                    || underUserHome(p, "/users/", "downloads/")
                    || underUserHome(p, "/home/", "downloads/");
        }
        String w = stripDriveLetter(p);
        return w != null
                && (w.startsWith("\\temp\\")
                || w.startsWith("\\windows\\temp\\")
                || underUserHome(w, "\\users\\", "appdata\\local\\temp\\")
                || underUserHome(w, "\\users\\", "downloads\\"));
    }

    /** 자동실행/지속성 경로인지 (소문자 기준). LaunchAgents 는 아래 세 곳에 놓일 때만 실제로 등록된다. */
    private static boolean isAutorunPath(String path) {
        String p = lower(path);
        if (p == null) {
            return false;
        }
        p = p.trim().replace("\"", "");   // 경로가 인용부호로 감싸여 오는 경우가 있다
        return FILE_AUTORUN_MARKERS.stream().anyMatch(p::contains)
                || p.startsWith("/library/launchagents/")
                || p.startsWith("/system/library/launchagents/")
                || underUserHome(p, "/users/", "library/launchagents/");
    }

    /** 홈 바로 아래가 tail 인지 (예: {@code /users/me/downloads/...}). 사용자명 한 칸을 안 강제하면 홈 밑이 아닌 동명 폴더까지 걸린다. */
    private static boolean underUserHome(String path, String homeRoot, String tail) {
        if (!path.startsWith(homeRoot)) {
            return false;
        }
        int userEnd = path.indexOf(homeRoot.charAt(0), homeRoot.length());
        return userEnd > homeRoot.length() && path.startsWith(tail, userEnd + 1);
    }

    /** Windows 경로면 드라이브 문자를 뗀 나머지, 아니면 null. 드라이브 없는 {@code \\users\\...} 도 그대로 받는다. */
    private static String stripDriveLetter(String path) {
        if (path.length() >= 3 && Character.isLetter(path.charAt(0)) && path.charAt(1) == ':' && path.charAt(2) == '\\') {
            return path.substring(2);
        }
        return path.startsWith("\\") ? path : null;
    }

    /** null 안전한 집합 포함 검사 (immutable Set 은 contains(null) 시 NPE). */
    private static boolean in(Set<String> set, String value) {
        return value != null && set.contains(value);
    }

    private static boolean isBaseline(String process) {
        return in(BASELINE_SAFE, process);
    }

    private static String lower(String s) {
        return s == null ? null : s.toLowerCase();
    }

    /** 조치 대상 프로세스 식별자 — 전체 경로(cmdline)가 있으면 우선, 없으면 프로세스명. responder 가 kill 에 사용. */
    private static String actTarget(Event e) {
        String cmd = e.cmdline();
        return (cmd != null && !cmd.isBlank()) ? cmd : e.process();
    }

    /** 근거 이벤트를 사람이 읽을 요약으로. */
    private static String summary(Event e) {
        if (isNetwork(e)) {
            return "network " + e.destIp() + ":" + e.destPort();
        }
        if (isScript(e)) {
            return "script " + e.process() + " (" + e.cmdline() + ")";
        }
        if (isFile(e)) {
            return "file " + e.cmdline();
        }
        return "process " + e.process() + " (parent " + e.parent() + ")";
    }
}
