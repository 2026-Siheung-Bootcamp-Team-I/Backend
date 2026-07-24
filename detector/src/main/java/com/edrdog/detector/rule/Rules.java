package com.edrdog.detector.rule;

import com.edrdog.detector.dto.Alert;
import com.edrdog.detector.dto.Event;

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

    /**
     * 정상적으로는 shell 을 직접 띄우지 않는 시스템 프로세스 — 자식으로 shell 이 뜨면 인젝션 의심.
     * explorer.exe 는 사용자가 터미널을 여는 정상 동작이라 오탐이 커서 제외한다.
     */
    private static final Set<String> SYSTEM_PARENTS = Set.of(
            "services.exe", "lsass.exe");

    /** 다운로드로 간주하는 목적지 포트 (HTTP/HTTPS 계열). */
    private static final Set<Integer> DOWNLOAD_PORTS = Set.of(80, 443, 8080);

    /** C2 비커닝 판정 임계치: 같은 목적지로 이 횟수 이상 반복 연결. */
    private static final int BEACON_THRESHOLD = 3;

    /** base64 blob 로 간주하는 최소 연속 길이 (인코딩된 페이로드 추정). */
    private static final int BASE64_MIN_LEN = 24;

    /** baseline: 알려진 정상 프로세스 — 룰에 걸려도 오탐이므로 억제. */
    private static final Set<String> BASELINE_SAFE = Set.of(
            "onedrive.exe", "teams.exe", "gupdate.exe", "msedgeupdate.exe", "update.exe");

    /**
     * 현재 이벤트가 선행 버퍼와 상관되어 룰을 완성하면 Alert 반환. 여러 룰 매칭 시 가장 심각한 것 채택.
     * CRITICAL 룰을 먼저 시도한 뒤 HIGH 룰을 시도하고, 첫 매칭을 반환한다.
     */
    public static Optional<Alert> evaluate(List<Event> prior, Event current) {
        if (current == null || current.host() == null) {
            return Optional.empty();
        }
        // CRITICAL 먼저
        Optional<Alert> alert = downloadAndExecute(prior, current);
        if (alert.isPresent()) {
            return alert;
        }
        alert = lsassAccess(current);
        if (alert.isPresent()) {
            return alert;
        }
        alert = defenseEvasion(current);
        if (alert.isPresent()) {
            return alert;
        }
        // 그다음 HIGH. 2-이벤트 상관 룰(R1)을 단일-이벤트 인코딩 휴리스틱보다 먼저 시도해
        // office 매크로 체인이 ENCODED_POWERSHELL 이 아니라 더 구체적인 R1 로 판정되게 한다.
        alert = c2Beaconing(prior, current);
        if (alert.isPresent()) {
            return alert;
        }
        alert = suspiciousParentChild(current);
        if (alert.isPresent()) {
            return alert;
        }
        alert = suspiciousProcessChain(prior, current);
        if (alert.isPresent()) {
            return alert;
        }
        return encodedPowershell(current);
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
        Event dl = download.get();
        return Optional.of(new Alert(
                current.host(),
                "DOWNLOAD_AND_EXECUTE",
                "T1105+T1204",
                Alert.SEV_CRITICAL,
                Alert.actionFor(Alert.SEV_CRITICAL),
                current.ts(),
                List.of(summary(dl), summary(current)),
                nz(dl.destIp()),
                dl.destPort()));
    }

    /** LSASS_ACCESS T1003.001: lsass 대상 자격증명 덤프 도구 사용. */
    private static Optional<Alert> lsassAccess(Event current) {
        if (!isProcess(current) || isBaseline(lower(current.process()))) {
            return Optional.empty();
        }
        String cmd = lower(current.cmdline());
        if (cmd == null || !cmd.contains("lsass")) {
            return Optional.empty();
        }
        boolean dumpTool = cmd.contains("procdump") || cmd.contains("minidump")
                || cmd.contains("comsvcs") || cmd.contains("-ma ") || cmd.contains("tasklist");
        if (!dumpTool) {
            return Optional.empty();
        }
        return Optional.of(processAlert(current, "LSASS_ACCESS", "T1003.001", Alert.SEV_CRITICAL));
    }

    /** DEFENSE_EVASION T1562: AV/방화벽 무력화 명령. */
    private static Optional<Alert> defenseEvasion(Event current) {
        if (!isProcess(current) || isBaseline(lower(current.process()))) {
            return Optional.empty();
        }
        String cmd = lower(current.cmdline());
        if (cmd == null) {
            return Optional.empty();
        }
        boolean tamper =
                (cmd.contains("netsh advfirewall set") && cmd.contains("off"))
                || (cmd.contains("set-mppreference") && cmd.contains("-disable"))
                || cmd.contains("sc stop windefend")
                || cmd.contains("sc config windefend")
                || (cmd.contains("stop-service") && cmd.contains("windefend"));
        if (!tamper) {
            return Optional.empty();
        }
        return Optional.of(processAlert(current, "DEFENSE_EVASION", "T1562", Alert.SEV_CRITICAL));
    }

    /** C2_BEACONING T1071: 같은 목적지로 반복 연결 (임계치 이상). */
    private static Optional<Alert> c2Beaconing(List<Event> prior, Event current) {
        if (!isNetwork(current)) {
            return Optional.empty();
        }
        String dest = current.destIp();
        if (dest == null || dest.isEmpty()) {
            return Optional.empty();
        }
        long sameDest = prior.stream()
                .filter(Rules::isNetwork)
                .filter(e -> dest.equals(e.destIp()))
                .count();
        if (sameDest + 1 < BEACON_THRESHOLD) {
            return Optional.empty();
        }
        return Optional.of(new Alert(
                current.host(),
                "C2_BEACONING",
                "T1071",
                Alert.SEV_HIGH,
                Alert.actionFor(Alert.SEV_HIGH),
                current.ts(),
                List.of(summary(current)),
                dest,
                current.destPort()));
    }

    /** SUSPICIOUS_PARENT_CHILD T1055: 시스템 프로세스(services/explorer/lsass)가 shell 을 자식으로 실행. */
    private static Optional<Alert> suspiciousParentChild(Event current) {
        if (!isProcess(current)) {
            return Optional.empty();
        }
        String child = lower(current.process());
        String parent = lower(current.parent());
        if (!in(SHELLS, child) || !in(SYSTEM_PARENTS, parent) || isBaseline(child)) {
            return Optional.empty();
        }
        return Optional.of(processAlert(current, "SUSPICIOUS_PARENT_CHILD", "T1055", Alert.SEV_HIGH));
    }

    /** ENCODED_POWERSHELL T1059.001: powershell 인코딩 명령 실행. */
    private static Optional<Alert> encodedPowershell(Event current) {
        if (!isProcess(current) || isBaseline(lower(current.process()))) {
            return Optional.empty();
        }
        if (!"powershell.exe".equals(lower(current.process()))) {
            return Optional.empty();
        }
        String cmd = lower(current.cmdline());
        if (cmd == null) {
            return Optional.empty();
        }
        boolean encodedFlag = cmd.contains("-enc") || cmd.contains("-encodedcommand")
                || cmd.contains("-e ") || hasBase64Blob(current.cmdline());
        if (!encodedFlag) {
            return Optional.empty();
        }
        return Optional.of(processAlert(current, "ENCODED_POWERSHELL", "T1059.001", Alert.SEV_HIGH));
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
                "",
                0));
    }

    /** 단일 process 이벤트만 근거로 하는 룰의 Alert 생성 (network 근거 없음 → destIp="", destPort=0). */
    private static Alert processAlert(Event current, String ruleId, String mitre, String severity) {
        return new Alert(
                current.host(),
                ruleId,
                mitre,
                severity,
                Alert.actionFor(severity),
                current.ts(),
                List.of(summary(current)),
                "",
                0);
    }

    private static boolean isProcess(Event e) {
        return Event.TYPE_PROCESS.equals(e.type());
    }

    private static boolean isNetwork(Event e) {
        return Event.TYPE_NETWORK.equals(e.type());
    }

    /** null 안전한 집합 포함 검사 (immutable Set 은 contains(null) 시 NPE). */
    private static boolean in(Set<String> set, String value) {
        return value != null && set.contains(value);
    }

    private static boolean isBaseline(String process) {
        return in(BASELINE_SAFE, process);
    }

    /** cmdline 에 인코딩된 페이로드로 추정되는 긴 base64 연속 토큰이 있는지. */
    private static boolean hasBase64Blob(String cmdline) {
        if (cmdline == null) {
            return false;
        }
        int run = 0;
        for (int i = 0; i < cmdline.length(); i++) {
            char c = cmdline.charAt(i);
            boolean b64 = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
            if (b64) {
                run++;
                if (run >= BASE64_MIN_LEN) {
                    return true;
                }
            } else {
                run = 0;
            }
        }
        return false;
    }

    private static String lower(String s) {
        return s == null ? null : s.toLowerCase();
    }

    /** null → 빈 문자열. */
    private static String nz(String s) {
        return s == null ? "" : s;
    }

    /** 근거 이벤트를 사람이 읽을 요약으로. */
    private static String summary(Event e) {
        if (isNetwork(e)) {
            return "network " + e.destIp() + ":" + e.destPort();
        }
        return "process " + e.process() + " (parent " + e.parent() + ")";
    }
}
