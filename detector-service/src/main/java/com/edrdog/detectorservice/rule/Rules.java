package com.edrdog.detectorservice.rule;

import com.edrdog.detectorservice.dto.Alert;
import com.edrdog.detectorservice.dto.Event;

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
        return Optional.of(new Alert(
                current.host(),
                "SUSPICIOUS_PROCESS_CHAIN",
                "T1059",
                Alert.SEV_HIGH,
                Alert.actionFor(Alert.SEV_HIGH),
                current.ts(),
                List.of(summary(officeExec.get()), summary(current)),
                current.tenantId(),
                actTarget(current)));
    }

    /**
     * R2 T1105+T1204: network 다운로드 → 이후 process 실행.
     *
     * <p>판정은 <b>이벤트 시각</b> 순서로 한다. 도착 순서로만 보면 이 조합을 거의 놓친다.
     * 네트워크 이벤트는 Zeek 가 연결 종료 후에 기록하고 전송기가 묶어 보내서 항상 늦게 도착하는데,
     * 실행 이벤트는 osquery 가 바로 올린다. 실기기에서 R2 가 한 번도 발화하지 않은 원인이었다.
     * 그래서 어느 쪽이 나중에 도착하든, 시각상 다운로드가 먼저면 판정한다.
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
                    .map(exec -> new Alert(
                            exec.host(),
                            "DOWNLOAD_AND_EXECUTE",
                            "T1105+T1204",
                            Alert.SEV_CRITICAL,
                            Alert.actionFor(Alert.SEV_CRITICAL),
                            exec.ts(),
                            List.of(summary(current), summary(exec)),
                            exec.tenantId(),
                            actTarget(exec)));
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
        return Optional.of(new Alert(
                current.host(),
                "DOWNLOAD_AND_EXECUTE",
                "T1105+T1204",
                Alert.SEV_CRITICAL,
                Alert.actionFor(Alert.SEV_CRITICAL),
                current.ts(),
                List.of(summary(download.get()), summary(current)),
                current.tenantId(),
                actTarget(current)));
    }

    /** R3 T1059: 임시/다운로드 경로에서 실행된 스크립트 (저심각 point 룰). */
    private static Optional<Alert> scriptFromTempPath(Event current) {
        if (!isScript(current) || !pathArgumentHasMarker(current.cmdline(), SCRIPT_TEMP_MARKERS)) {
            return Optional.empty();
        }
        return Optional.of(new Alert(
                current.host(),
                "SCRIPT_FROM_TEMP_PATH",
                "T1059",
                Alert.SEV_MEDIUM,
                Alert.actionFor(Alert.SEV_MEDIUM),
                current.ts(),
                List.of(summary(current)),
                current.tenantId(),
                actTarget(current)));
    }

    /** R4 T1547: 자동실행/시작 경로에 생성된 파일 (지속성 확보, 저심각 point 룰). */
    private static Optional<Alert> fileInAutorunPath(Event current) {
        if (!isFile(current) || !pathHasMarker(current.cmdline(), FILE_AUTORUN_MARKERS)) {
            return Optional.empty();
        }
        return Optional.of(new Alert(
                current.host(),
                "FILE_IN_AUTORUN_PATH",
                "T1547",
                Alert.SEV_MEDIUM,
                Alert.actionFor(Alert.SEV_MEDIUM),
                current.ts(),
                List.of(summary(current)),
                current.tenantId(),
                actTarget(current)));
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

    /** 경로(소문자화)에 표식 중 하나라도 포함되면 true. */
    private static boolean pathHasMarker(String path, Set<String> markers) {
        String p = lower(path);
        return p != null && markers.stream().anyMatch(p::contains);
    }

    /** 셸 연산자 — 여기부터는 실행 대상이 아니라 출력/후속 명령이라 판정에서 제외한다. */
    private static final Set<String> SHELL_OPERATORS = Set.of(">", ">>", ">|", "<", "|", "||", "&&", ";", "&");

    /**
     * 실행된 파일 자체(argv[0])의 경로에 표식이 있는지 본다.
     *
     * <p>인자까지 보면 정상 프로세스가 임시 경로를 인자로 받는 것만으로 걸린다. 실제로
     * {@code find /private/tmp/...} 와 {@code mount_apfs ... /private/tmp/PKInstallSandbox/...} 가
     * CRITICAL 로 올라갔다. macOS 는 설치·업데이트 과정에서 /private/tmp 를 상시 쓴다.
     * "받아온 파일을 실행"이 R2 의 의미이므로 실행 파일 경로만 판단 근거로 쓴다.
     */
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
