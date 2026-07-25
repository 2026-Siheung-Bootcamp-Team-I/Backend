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

    /** R2 T1105+T1204: 버퍼의 network 다운로드 → 이후 process 실행. */
    private static Optional<Alert> downloadAndExecute(List<Event> prior, Event current) {
        if (!isProcess(current) || isBaseline(lower(current.process()))) {
            return Optional.empty();
        }
        Optional<Event> download = prior.stream()
                .filter(Rules::isNetwork)
                .filter(e -> DOWNLOAD_PORTS.contains(e.destPort()))
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
        if (!isScript(current) || !pathHasMarker(current.cmdline(), SCRIPT_TEMP_MARKERS)) {
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
