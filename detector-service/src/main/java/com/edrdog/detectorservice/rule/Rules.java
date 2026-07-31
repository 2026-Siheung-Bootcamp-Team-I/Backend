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

    /** 임시/다운로드 경로 표식 — 여기서 스크립트가 실행되면 저심각 의심(R3). 소문자 기준. */
    private static final Set<String> SCRIPT_TEMP_MARKERS = Set.of(
            "\\temp\\", "/tmp/", "\\downloads\\", "/downloads/", "appdata\\local\\temp");

    /** 자동실행/시작 경로 표식 — 여기에 파일이 생기면 지속성 확보 의심(R4). 소문자 기준. */
    private static final Set<String> FILE_AUTORUN_MARKERS = Set.of(
            "\\startup\\", "/launchagents/", "\\currentversion\\run");

    /**
     * 현재 이벤트가 선행 버퍼와 상관되어 룰을 완성하면 Alert 반환. 여러 룰 매칭 시 가장 심각한 것 채택.
     */
    public static Optional<Alert> evaluate(List<Event> prior, Event current) {
        if (current == null || current.host() == null) {
            return Optional.empty();
        }
        // 더 심각한 R2(CRITICAL) 를 먼저 시도
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
     *
     * <p>버퍼는 상태 크기 때문에 상한이 있는데, 실기기는 초당 십여 건씩 프로세스 이벤트를 낸다.
     * 전부 담으면 상한이 금방 차서 5분 윈도우가 사실상 십여 초로 줄고, 상관 룰이 발화하지 못한다.
     * 룰이 '선행'으로 실제 참조하는 것만 남긴다. 나머지는 현재 이벤트로 판정될 때 이미 쓰였다.
     *
     * <ul>
     *   <li>network: 다운로드 포트만 (R2)</li>
     *   <li>process: office 앱(R1 의 부모 후보) 또는 임시·다운로드 경로 실행(R2 역방향)</li>
     * </ul>
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
                    || executableHasMarker(e.cmdline(), SCRIPT_TEMP_MARKERS);
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
     *
     * <p>판정은 <b>이벤트 시각</b> 순서로 한다. 도착 순서로만 보면 이 조합을 거의 놓친다.
     * 예전 구성(네트워크는 Zeek, 프로세스는 osquery)에서 실기기 R2 가 한 번도 발화하지 않은 원인이
     * 이것이었다. Zeek 는 연결이 끝난 뒤에 기록하고 전송기가 묶어 보내서 네트워크 이벤트가 항상
     * 늦게 도착했다. 지금은 한 에이전트가 둘 다 보내지만, 센서마다 지연이 다른 것은 그대로라
     * 도착 순서에 기대지 않는다. 어느 쪽이 나중에 도착하든 시각상 다운로드가 먼저면 판정한다.
     */
    private static Optional<Alert> downloadAndExecute(List<Event> prior, Event current) {
        // 네트워크가 늦게 도착한 경우: 버퍼에서 그 뒤에 실행된 프로세스를 찾는다.
        if (isNetwork(current) && DOWNLOAD_PORTS.contains(current.destPort())) {
            return prior.stream()
                    .filter(Rules::isProcess)
                    .filter(e -> !isBaseline(lower(e.process())))
                    .filter(e -> executableHasMarker(e.cmdline(), SCRIPT_TEMP_MARKERS))
                    .filter(e -> e.ts() >= current.ts())   // 시각상 다운로드가 먼저여야 한다
                    .findFirst()
                    .map(exec -> alertOf("DOWNLOAD_AND_EXECUTE", "T1105+T1204", Alert.SEV_CRITICAL,
                            exec, List.of(current)));
        }
        if (!isProcess(current) || isBaseline(lower(current.process()))) {
            return Optional.empty();
        }
        // 받아온 것을 "실행"했는지가 핵심이다(T1105+T1204). 조건이 없으면 웹 접속 한 번 뒤의
        // 모든 프로세스 실행이 CRITICAL 이 된다. 인자까지 보면 정상 프로세스가 임시 경로를
        // 인자로 받는 경우(find /private/tmp/..., mount_apfs ... /private/tmp/PKInstallSandbox/...)
        // 까지 걸리므로, 실행된 파일 자체(argv[0])만 본다.
        if (!executableHasMarker(current.cmdline(), SCRIPT_TEMP_MARKERS)) {
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
        if (!isScript(current) || !pathArgumentHasMarker(current.cmdline(), SCRIPT_TEMP_MARKERS)) {
            return Optional.empty();
        }
        return Optional.of(alertOf("SCRIPT_FROM_TEMP_PATH", "T1059", Alert.SEV_MEDIUM,
                current, List.of()));
    }

    /** R4 T1547: 자동실행/시작 경로에 생성된 파일 (지속성 확보, 저심각 point 룰). */
    private static Optional<Alert> fileInAutorunPath(Event current) {
        if (!isFile(current) || !pathHasMarker(current.cmdline(), FILE_AUTORUN_MARKERS)) {
            return Optional.empty();
        }
        return Optional.of(alertOf("FILE_IN_AUTORUN_PATH", "T1547", Alert.SEV_MEDIUM,
                current, List.of()));
    }

    /**
     * 판정 결과 조립. 근거는 선행(prior) 뒤에 트리거를 붙인 순서이고, 따라서 <b>matched 의 마지막은 항상
     * 트리거</b>(= alert.ts 인 이벤트)다. api-service 가 알림에서 원본 이벤트를 되찾을 때 이 순서에 기댄다
     * (SourceEventMatcher). 서비스 경계를 넘는 규약이라 호출부가 순서를 틀릴 수 없도록 트리거를 여기서 붙인다.
     */
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

    /**
     * 근거 중 목적지를 관측한 이벤트 (없으면 null).
     *
     * <p>방금 도착한 이벤트 하나만 보면 안 된다. R2 는 다운로드(network)와 실행(process)을 상관하는데
     * 목적지를 아는 건 다운로드 쪽뿐이다. 네트워크가 늦게 도착한 갈래는 도착한 이벤트가 network 라
     * 목적지가 실리고, 정상 순서로 도착한 갈래는 process 라 목적지가 빈다. 같은 공격인데 도착 순서에
     * 따라 값이 갈리면 topology 화면에서 절반만 그려진다. 룰이 도착 순서에 독립적으로 판정하는 만큼
     * 목적지도 그래야 한다.
     */
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

    private static boolean pathHasMarker(String path, Set<String> markers) {
        String p = lower(path);
        return p != null && markers.stream().anyMatch(p::contains);
    }

    /** 셸 연산자 — 여기부터는 실행 대상이 아니라 출력/후속 명령이라 판정에서 제외한다. */
    private static final Set<String> SHELL_OPERATORS = Set.of(">", ">>", ">|", "<", "|", "||", "&&", ";", "&");

    /** 실행된 파일 자체(argv[0])만 본다. 인자까지 보면 정상 프로세스의 오탐이 난다(find/mount_apfs 사례, downloadAndExecute 참고). */
    private static boolean executableHasMarker(String cmdline, Set<String> markers) {
        String c = lower(cmdline);
        if (c == null || c.isBlank()) {
            return false;
        }
        String argv0 = c.trim().split("\\s+")[0];
        return markers.stream().anyMatch(argv0::contains);
    }

    /**
     * cmdline 에서 "실행 대상으로 보이는 경로 인자"에만 표식이 있는지 본다.
     *
     * <p>cmdline 전체를 문자열로 훑으면 실행과 무관한 위치의 경로까지 걸린다. 실제로
     * {@code ... && pwd -P >| /tmp/x} 처럼 리다이렉션 대상이 임시 경로라는 이유로 알림이 나갔다.
     * 그래서 셸 연산자가 나오면 거기서 끊고, 앞쪽 인자 중 경로처럼 생긴 토큰만 검사한다.
     */
    private static boolean pathArgumentHasMarker(String cmdline, Set<String> markers) {
        String c = lower(cmdline);
        if (c == null) {
            return false;
        }
        for (String token : c.split("\\s+")) {
            if (SHELL_OPERATORS.contains(token)) {
                return false;   // 연산자 뒤는 실행 대상이 아니다
            }
            boolean looksLikePath = token.contains("/") || token.contains("\\");
            if (looksLikePath && markers.stream().anyMatch(token::contains)) {
                return true;
            }
        }
        return false;
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
