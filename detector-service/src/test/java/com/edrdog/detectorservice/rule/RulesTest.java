package com.edrdog.detectorservice.rule;

import com.edrdog.detectorservice.dto.Alert;
import com.edrdog.detectorservice.support.TestEvents;
import com.edrdog.schema.Event;
import com.edrdog.schema.EventTypes;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/** 상관분석 룰 판정 순수 로직 테스트. 버퍼는 이미 윈도우로 정리됐다고 가정(윈도우 판정은 프로세서 책임). */
class RulesTest {

    private static final String HOST = "host-1";
    private static final String TENANT = "tenant-a";

    private Event process(String proc, String parent, long ts) {
        return TestEvents.of(HOST, EventTypes.PROCESS, ts, proc, parent, proc + " args", null, 0, null, null, null, TENANT);
    }

    /** pid/ppid 를 관측한 process 이벤트. 에이전트는 이 값을 detail JSON 으로 보낸다. */
    private Event process(String proc, String parent, long ts, int pid, int ppid) {
        return TestEvents.of(HOST, EventTypes.PROCESS, ts, proc, parent, proc + " args", null, 0, null,
                "{\"pid\":" + pid + ",\"ppid\":" + ppid + "}", null, TENANT);
    }

    /** cmdline 을 직접 주는 process 이벤트. R2 는 실행 경로(cmdline)를 본다. */
    private Event processFrom(String proc, String cmdline, long ts) {
        return TestEvents.of(HOST, EventTypes.PROCESS, ts, proc, "bash", cmdline, null, 0, null, null, null, TENANT);
    }

    private Event network(String destIp, int destPort, long ts) {
        return TestEvents.of(HOST, EventTypes.NETWORK, ts, null, null, null, destIp, destPort, null, null, null, TENANT);
    }

    private Event script(String proc, String fullCmdline, long ts) {
        return TestEvents.of(HOST, EventTypes.SCRIPT, ts, proc, "explorer.exe", fullCmdline, null, 0, null, null, null, TENANT);
    }

    private Event file(String name, String fullPath, long ts) {
        return TestEvents.of(HOST, EventTypes.FILE, ts, name, null, fullPath, null, 0, null, null, null, TENANT);
    }

    /** TLS 핸드셰이크(l7) 이벤트. 버전은 detail 에 온다(관측 형식: "TLS 1.3"). */
    private Event l7(String domain, String tlsVersion, long ts) {
        String detail = tlsVersion == null ? "{\"l7Protocol\":\"TLS\"}"
                : "{\"l7Protocol\":\"TLS\",\"tlsVersion\":\"" + tlsVersion + "\"}";
        return TestEvents.of(HOST, EventTypes.L7, ts, "curl", null, null, "203.0.113.9", 443, domain,
                detail, null, TENANT);
    }

    /** action 을 관측한 file 이벤트. 에이전트는 CREATE/WRITE/RENAME/DELETE 를 detail 에 싣는다. */
    private Event file(String name, String fullPath, long ts, String action) {
        return TestEvents.of(HOST, EventTypes.FILE, ts, name, null, fullPath, null, 0, null,
                "{\"action\":\"" + action + "\"}", null, TENANT);
    }

    @Test
    @DisplayName("R1: office앱 exec 후 그 자식으로 shell 실행 → SUSPICIOUS_PROCESS_CHAIN(T1059, HIGH, kill)")
    void r1_officeThenShell_alerts() {
        List<Event> buffer = List.of(process("winword.exe", "explorer.exe", 1000));
        Event current = process("powershell.exe", "winword.exe", 2000);

        Optional<Alert> alert = Rules.evaluate(buffer, current);

        assertThat(alert).isPresent();
        Alert a = alert.get();
        assertThat(a.host()).isEqualTo(HOST);
        assertThat(a.ruleId()).isEqualTo("SUSPICIOUS_PROCESS_CHAIN");
        assertThat(a.mitre()).isEqualTo("T1059");
        assertThat(a.severity()).isEqualTo(Alert.SEV_HIGH);
        assertThat(a.action()).isEqualTo(Alert.ACTION_KILL);
        assertThat(a.ts()).isEqualTo(2000);
        assertThat(a.matched()).hasSize(2);
        assertThat(a.tenantId()).isEqualTo(TENANT);
    }

    @Test
    @DisplayName("R1 음성: shell 이지만 부모가 office앱이 아니면 미판정")
    void r1_shellWithNonOfficeParent_noAlert() {
        List<Event> buffer = List.of(process("explorer.exe", "userinit.exe", 1000));
        Event current = process("powershell.exe", "explorer.exe", 2000);

        assertThat(Rules.evaluate(buffer, current)).isEmpty();
    }

    @Test
    @DisplayName("R1 음성: 부모가 office앱이지만 그 office앱 exec 가 버퍼에 없으면 미판정(시퀀스 미완성)")
    void r1_noOfficeExecInBuffer_noAlert() {
        List<Event> buffer = List.of();
        Event current = process("powershell.exe", "winword.exe", 2000);

        assertThat(Rules.evaluate(buffer, current)).isEmpty();
    }

    @Test
    @DisplayName("R1: pid/ppid 를 관측했으면 계보가 실제로 이어지는 office exec 를 근거로 고른다")
    void r1_picksOfficeExecByPidLineage() {
        // 같은 office 앱이 여러 번 떠 있으면 이름만으로는 어느 쪽이 부모인지 알 수 없다.
        List<Event> buffer = List.of(
                process("winword.exe", "explorer.exe", 900, 100, 1),
                process("winword.exe", "finder.exe", 1000, 200, 1));
        Event current = process("powershell.exe", "winword.exe", 2000, 300, 200);

        Optional<Alert> alert = Rules.evaluate(buffer, current);

        assertThat(alert).isPresent();
        assertThat(alert.get().matched()).first()
                .isEqualTo("process winword.exe (parent finder.exe)");
    }

    @Test
    @DisplayName("R1 음성: 부모 이름은 같지만 pid/ppid 계보가 안 이어지면 미판정")
    void r1_pidLineageMismatch_noAlert() {
        List<Event> buffer = List.of(process("winword.exe", "explorer.exe", 1000, 100, 1));
        Event current = process("powershell.exe", "winword.exe", 2000, 300, 999);

        assertThat(Rules.evaluate(buffer, current)).isEmpty();
    }

    @Test
    @DisplayName("R1 양성: 한쪽이라도 pid/ppid 를 못 봤으면 이름 상관으로 남긴다")
    void r1_missingPid_fallsBackToNameMatch() {
        // 관측하지 못한 값으로 탐지를 깎으면 pid 를 못 보내는 수집기에서 R1 이 통째로 죽는다.
        List<Event> buffer = List.of(process("winword.exe", "explorer.exe", 1000));
        Event current = process("powershell.exe", "winword.exe", 2000, 300, 200);

        assertThat(Rules.evaluate(buffer, current))
                .isPresent()
                .get()
                .extracting(Alert::ruleId)
                .isEqualTo("SUSPICIOUS_PROCESS_CHAIN");
    }

    @Test
    @DisplayName("R2: network 다운로드 후 같은 host 에서 process 실행 → DOWNLOAD_AND_EXECUTE(T1105+T1204, CRITICAL, kill)")
    void r2_downloadThenExecute_alerts() {
        List<Event> buffer = List.of(network("203.0.113.9", 443, 1000));
        Event current = processFrom("evil.exe", "/tmp/evil.exe --run", 2000);

        Optional<Alert> alert = Rules.evaluate(buffer, current);

        assertThat(alert).isPresent();
        Alert a = alert.get();
        assertThat(a.ruleId()).isEqualTo("DOWNLOAD_AND_EXECUTE");
        assertThat(a.mitre()).isEqualTo("T1105+T1204");
        assertThat(a.severity()).isEqualTo(Alert.SEV_CRITICAL);
        assertThat(a.action()).isEqualTo(Alert.ACTION_KILL);
        assertThat(a.ts()).isEqualTo(2000);
        assertThat(a.matched()).hasSize(2);
    }

    @Test
    @DisplayName("R2 음성: 받아온 뒤라도 임시·다운로드 경로가 아닌 실행은 미판정 (평범한 앱 실행)")
    void r2_executeFromNormalPath_noAlert() {
        // 웹 접속 후 정상 앱을 실행하는 건 일상이다. 여기까지 CRITICAL 로 올리면 실사용에서 오탐만 남는다.
        List<Event> buffer = List.of(network("203.0.113.9", 443, 1000));
        Event current = processFrom("Slack", "/Applications/Slack.app/Contents/MacOS/Slack", 2000);

        assertThat(Rules.evaluate(buffer, current)).isEmpty();
    }

    @Test
    @DisplayName("R2 양성: 다운로드 폴더에서 실행해도 잡는다")
    void r2_executeFromDownloads_alerts() {
        List<Event> buffer = List.of(network("203.0.113.9", 80, 1000));
        Event current = processFrom("setup", "/Users/me/Downloads/setup --silent", 2000);

        Optional<Alert> alert = Rules.evaluate(buffer, current);

        assertThat(alert).isPresent();
        assertThat(alert.get().ruleId()).isEqualTo("DOWNLOAD_AND_EXECUTE");
    }

    @Test
    @DisplayName("R2 음성: 인자만 임시 경로인 정상 프로세스는 미판정 (실제 오탐 사례)")
    void r2_tempPathOnlyInArgument_noAlert() {
        // 실제로 Slack 까지 갔던 오탐 2건. 실행된 파일은 /usr/bin/find, /sbin/mount_apfs 이고
        // 임시 경로는 인자일 뿐이다. macOS 는 설치·업데이트 과정에서 /private/tmp 를 상시 사용한다.
        List<Event> buffer = List.of(network("203.0.113.9", 443, 1000));

        assertThat(Rules.evaluate(buffer,
                processFrom("find", "find /private/tmp/scratch -name *.py", 2000))).isEmpty();
        assertThat(Rules.evaluate(buffer,
                processFrom("mount_apfs", "/sbin/mount_apfs -o nobrowse /dev/disk1 /private/tmp/PKInstallSandbox/Root", 2100))).isEmpty();
    }

    @Test
    @DisplayName("R2 음성: 실기기 10분 캡처에서 관측된, 임시 경로를 인자로만 쓰는 실행들")
    void r2_observedTempPathArguments_noAlert() {
        // eslogger 로 이 맥에서 직접 받은 명령줄이다. 지어낸 경로로만 덮으면 같은 종류가 다시 샌다.
        List<Event> buffer = List.of(network("203.0.113.9", 443, 1000));
        List<String> observed = List.of(
                "/usr/bin/open -n /Applications/Orca.app/Contents/Resources/Orca Computer Use.app --args "
                        + "--permission-status-file /var/folders/y0/7xl0d3v94fs5fv14tcch9gsh0000gn/T/"
                        + "orca-computer-use-permissions-d2wpB0/status.json",
                "/Applications/Orca.app/Contents/Resources/Orca Computer Use.app/Contents/MacOS/orca-computer-use-macos "
                        + "--permission-status-file /var/folders/y0/7xl0d3v94fs5fv14tcch9gsh0000gn/T/status",
                "/usr/bin/find /private/var/tmp/sooplive -maxdepth 1 -name *.part -mmin -5");

        for (String cmdline : observed) {
            assertThat(Rules.evaluate(buffer, processFrom("x", cmdline, 2000)))
                    .as(cmdline)
                    .isEmpty();
        }
    }

    @Test
    @DisplayName("R2 음성: network 이벤트의 포트가 다운로드 포트가 아니면 미판정")
    void r2_nonDownloadPort_noAlert() {
        List<Event> buffer = List.of(network("203.0.113.9", 22, 1000));
        Event current = process("evil.exe", "cmd.exe", 2000);

        assertThat(Rules.evaluate(buffer, current)).isEmpty();
    }

    @Test
    @DisplayName("baseline: 알려진 정상 프로세스는 다운로드 후 실행이어도 억제")
    void baseline_knownBenignProcess_suppressed() {
        List<Event> buffer = List.of(network("203.0.113.9", 443, 1000));
        Event current = process("onedrive.exe", "explorer.exe", 2000);

        assertThat(Rules.evaluate(buffer, current)).isEmpty();
    }

    @Test
    @DisplayName("R3: 임시/다운로드 경로에서 스크립트 실행 → SCRIPT_FROM_TEMP_PATH(T1059, MEDIUM, notify)")
    void r3_scriptFromTempPath_alerts() {
        Event current = script("powershell.exe",
                "powershell -File C:\\Users\\victim\\Downloads\\setup.ps1", 3000);

        Optional<Alert> alert = Rules.evaluate(List.of(), current);

        assertThat(alert).isPresent();
        Alert a = alert.get();
        assertThat(a.ruleId()).isEqualTo("SCRIPT_FROM_TEMP_PATH");
        assertThat(a.mitre()).isEqualTo("T1059");
        assertThat(a.severity()).isEqualTo(Alert.SEV_MEDIUM);
        assertThat(a.action()).isEqualTo(Alert.ACTION_NOTIFY);
        assertThat(a.ts()).isEqualTo(3000);
        assertThat(a.matched()).hasSize(1);
        assertThat(a.tenantId()).isEqualTo(TENANT);
    }

    @Test
    @DisplayName("R3 음성: 스크립트지만 정상 경로면 미판정")
    void r3_scriptFromNormalPath_noAlert() {
        Event current = script("powershell.exe",
                "powershell -File C:\\Program Files\\App\\run.ps1", 3000);

        assertThat(Rules.evaluate(List.of(), current)).isEmpty();
    }

    @Test
    @DisplayName("R3 음성: 리다이렉션 뒤에 /tmp/ 가 나올 뿐이면 미판정 (실제 오탐 사례)")
    void r3_tempPathOnlyAfterRedirect_noAlert() {
        // 실제로 Slack 까지 갔던 오탐. 실행된 스크립트는 홈 디렉터리에 있고
        // /tmp/ 는 출력 리다이렉션 대상일 뿐인데 cmdline 전체 문자열 검사에 걸렸다.
        Event current = script("zsh",
                "/bin/zsh -c source /Users/me/.claude/shell-snapshots/snap.sh && pwd -P >| /tmp/claude-cwd", 3000);

        assertThat(Rules.evaluate(List.of(), current)).isEmpty();
    }

    @Test
    @DisplayName("R3 양성: 명령 구분자 뒤의 임시 경로 실행도 잡는다 (구분자에서 멈추면 회피된다)")
    void r3_afterCommandSeparator_alerts() {
        List<String> evasions = List.of(
                "/bin/zsh -c true && /tmp/evil.sh",
                "/bin/sh -c echo hi || /private/tmp/evil.sh",
                "/bin/bash -c ls ; /Users/me/Downloads/evil.sh");

        for (String cmdline : evasions) {
            assertThat(Rules.evaluate(List.of(), script("sh", cmdline, 3000)))
                    .as(cmdline)
                    .isPresent()
                    .get()
                    .extracting(Alert::ruleId)
                    .isEqualTo("SCRIPT_FROM_TEMP_PATH");
        }
    }

    @Test
    @DisplayName("R3 음성: 리다이렉션 대상은 건너뛰되 그 뒤 명령은 계속 본다")
    void r3_redirectTargetSkipped_restStillScanned() {
        // 출력 대상은 실행 대상이 아니라 건너뛴다. 건너뛰는 것과 검사를 멈추는 것은 다르다.
        assertThat(Rules.evaluate(List.of(), script("zsh", "/bin/zsh -c pwd -P >| /tmp/cwd && echo done", 3000)))
                .isEmpty();
        assertThat(Rules.evaluate(List.of(), script("zsh", "/bin/zsh -c pwd -P >| /tmp/cwd && /tmp/evil.sh", 3000)))
                .isPresent();
    }

    @Test
    @DisplayName("R3 음성: 실기기 40분 수집에서 관측된 셸 래퍼는 그대로 미판정")
    void r3_observedShellWrappers_noAlert() {
        // 로컬 파이프라인에 에이전트를 붙여 받은 원문이다. 임시 경로가 리다이렉션 대상이거나
        // eval 인용부호 안에 통째로 들어 있어 실행 대상이 아니다.
        List<String> observed = List.of(
                "/bin/zsh -c source /Users/dhkim/.claude/shell-snapshots/snapshot-zsh-1785696131308-9w5scr.sh "
                        + "2>/dev/null || true && setopt NO_EXTENDED_GLOB NO_BARE_GLOB_QUAL 2>/dev/null || true && "
                        + "{ \\builtin unalias -- 'unsetenv'; \\builtin unset -f -- 'unsetenv'; } >/dev/null 2>&1 || true && "
                        + "eval 'grep -rn \"RequestMapping\" detector-service/src/main/java | head -5' "
                        + "< /dev/null && pwd -P >| /tmp/claude-8768-cwd",
                "/bin/zsh -c source /Users/dhkim/.claude/shell-snapshots/snapshot-zsh-1785696131308-9w5scr.sh "
                        + "2>/dev/null || true && eval 'S=/private/tmp/claude-501/-Users-dhkim-orca-workspaces-Backend-issue-178/"
                        + "f8381d23-5acc-4245-b989-2eb599d2bd07/scratchpad; grep -iE \"enroll\" $S/collector.log | tail -6' "
                        + "< /dev/null && pwd -P >| /tmp/claude-383d-cwd");

        for (String cmdline : observed) {
            assertThat(Rules.evaluate(List.of(), script("zsh", cmdline, 3000)))
                    .as(cmdline)
                    .isEmpty();
        }
    }

    @Test
    @DisplayName("R3 양성: 인터프리터가 임시 경로 스크립트를 인자로 실행하면 잡는다")
    void r3_interpreterRunsTempScript_alerts() {
        Event current = script("zsh", "/bin/zsh /tmp/evil.sh", 3000);

        Optional<Alert> alert = Rules.evaluate(List.of(), current);

        assertThat(alert).isPresent();
        assertThat(alert.get().ruleId()).isEqualTo("SCRIPT_FROM_TEMP_PATH");
    }

    @Test
    @DisplayName("R3 음성: 앱 내부 tmp 폴더는 시스템 임시 경로가 아니다 (실제 오탐 사례)")
    void r3_appInternalTempFolder_noAlert() {
        // 배포 서버에서 R3 알림 42건이 전부 이것이었다. AhnLab 보안제품이 자기 업데이트 plist 를
        // 다루는 정상 동작인데, /Applications/AhnLab/ASTx/tmp/ 안의 '/tmp/' 조각에 걸렸다.
        List<String> observed = List.of(
                "/bin/sh -c /bin/launchctl unload \"/Applications/AhnLab/ASTx/tmp/com.ahnlab.astx.astxUpdate.plist\"",
                "/bin/sh -c /bin/launchctl load \"/Applications/AhnLab/ASTx/tmp/com.ahnlab.astx.astxUpdate.plist\"",
                "/bin/sh -c /usr/sbin/chown -R root:wheel \"/Applications/AhnLab/ASTx/tmp/com.ahnlab.astx.astxUpdate.plist\"",
                "/bin/bash -c /bin/launchctl unload \"/Applications/AhnLab/ASTx/tmp/com.ahnlab.astx.astxUpdate.plist\"",
                "/bin/bash -c /bin/launchctl load \"/Applications/AhnLab/ASTx/tmp/com.ahnlab.astx.astxUpdate.plist\"",
                "/bin/bash -c /usr/sbin/chown -R root:wheel \"/Applications/AhnLab/ASTx/tmp/com.ahnlab.astx.astxUpdate.plist\"");

        for (String cmdline : observed) {
            assertThat(Rules.evaluate(List.of(), script("sh", cmdline, 3000)))
                    .as(cmdline)
                    .isEmpty();
        }
    }

    @Test
    @DisplayName("R3 양성: /private/tmp/ 는 macOS 의 진짜 시스템 임시 경로라 계속 잡는다 (실제 관측 사례)")
    void r3_realSystemTempPath_stillAlerts() {
        // 배포 서버에서 관측된 개발 도구 노이즈지만 룰이 의도대로 동작한 것이다.
        // 여기를 빼면 공격자가 쓰는 바로 그 경로를 허용하게 된다.
        List<String> observed = List.of(
                "/bin/bash -c tsc --noEmit -p /private/tmp/claude-501/proj/scratchpad/tsconfig.check.json",
                "/usr/bin/python3 - /private/tmp/claude-501/proj/scratchpad/typecheck/src/api/demo.ts");

        for (String cmdline : observed) {
            assertThat(Rules.evaluate(List.of(), script("sh", cmdline, 3000)))
                    .as(cmdline)
                    .isPresent()
                    .get()
                    .extracting(Alert::ruleId)
                    .isEqualTo("SCRIPT_FROM_TEMP_PATH");
        }
    }

    @Test
    @DisplayName("R3 양성: 경로에 인용부호가 붙어 있어도 잡는다")
    void r3_quotedTempPath_alerts() {
        Event current = script("powershell.exe",
                "powershell -File \"C:\\Users\\victim\\Downloads\\setup.ps1\"", 3000);

        assertThat(Rules.evaluate(List.of(), current))
                .isPresent()
                .get()
                .extracting(Alert::ruleId)
                .isEqualTo("SCRIPT_FROM_TEMP_PATH");
    }

    @Test
    @DisplayName("R2 음성: 앱 내부 tmp 폴더에서 실행된 것은 다운로드-실행이 아니다")
    void r2_executeFromAppInternalTempFolder_noAlert() {
        // R3 오탐과 같은 결함이다. R2 도 같은 경로 판정을 쓴다.
        List<Event> buffer = List.of(network("203.0.113.9", 443, 1000));
        Event current = processFrom("astxUpdate", "/Applications/AhnLab/ASTx/tmp/astxUpdate", 2000);

        assertThat(Rules.evaluate(buffer, current)).isEmpty();
    }

    @Test
    @DisplayName("R4: 자동실행(시작프로그램) 경로에 파일 생성 → FILE_IN_AUTORUN_PATH(T1547, MEDIUM, notify)")
    void r4_fileInAutorunPath_alerts() {
        Event current = file("evil.lnk",
                "C:\\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.lnk",
                4000);

        Optional<Alert> alert = Rules.evaluate(List.of(), current);

        assertThat(alert).isPresent();
        Alert a = alert.get();
        assertThat(a.ruleId()).isEqualTo("FILE_IN_AUTORUN_PATH");
        assertThat(a.mitre()).isEqualTo("T1547");
        assertThat(a.severity()).isEqualTo(Alert.SEV_MEDIUM);
        assertThat(a.action()).isEqualTo(Alert.ACTION_NOTIFY);
        assertThat(a.ts()).isEqualTo(4000);
        assertThat(a.matched()).hasSize(1);
    }

    @Test
    @DisplayName("R4 음성: 파일이지만 일반 경로면 미판정")
    void r4_fileInNormalPath_noAlert() {
        Event current = file("report.docx", "C:\\Users\\victim\\Documents\\report.docx", 4000);

        assertThat(Rules.evaluate(List.of(), current)).isEmpty();
    }

    @Test
    @DisplayName("R4 양성: macOS 실제 자동실행 경로(LaunchAgents)의 plist 는 잡는다")
    void r4_realLaunchAgentPaths_alert() {
        List<String> autorunPaths = List.of(
                "/Library/LaunchAgents/com.evil.agent.plist",
                "/System/Library/LaunchAgents/com.evil.agent.plist",
                "/Users/victim/Library/LaunchAgents/com.evil.agent.plist");

        for (String path : autorunPaths) {
            assertThat(Rules.evaluate(List.of(), file("com.evil.agent.plist", path, 4000)))
                    .as(path)
                    .isPresent()
                    .get()
                    .extracting(Alert::ruleId)
                    .isEqualTo("FILE_IN_AUTORUN_PATH");
        }
    }

    @Test
    @DisplayName("R4 음성: 경로에 startup 폴더가 들어 있을 뿐인 일반 파일은 미판정 (#174 와 같은 조각 검사 결함)")
    void r4_startupFragmentInOrdinaryPath_noAlert() {
        // 실제 시작프로그램은 시작 메뉴 아래에만 있다. 조각으로 찾으면 이름이 startup 인 폴더가 전부 걸린다.
        List<String> ordinary = List.of(
                "C:\\dev\\myapp\\startup\\config.json",
                "C:\\Users\\me\\projects\\server\\startup\\init.bat",
                "C:\\backup\\CurrentVersion\\Runtime\\cache.dat");

        for (String path : ordinary) {
            assertThat(Rules.evaluate(List.of(), file("x", path, 4000)))
                    .as(path)
                    .isEmpty();
        }
    }

    @Test
    @DisplayName("R4 양성: 실제 자동실행 위치(사용자·전체 시작프로그램, 레지스트리 Run 키)는 계속 잡는다")
    void r4_realWindowsAutorunLocations_alert() {
        List<String> autorun = List.of(
                "C:\\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.lnk",
                "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\evil.lnk",
                "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\evil");

        for (String path : autorun) {
            assertThat(Rules.evaluate(List.of(), file("evil", path, 4000)))
                    .as(path)
                    .isPresent()
                    .get()
                    .extracting(Alert::ruleId)
                    .isEqualTo("FILE_IN_AUTORUN_PATH");
        }
    }

    @Test
    @DisplayName("R4 양성: LaunchDaemons 는 에이전트가 감시하는 경로라 판정에도 있어야 한다")
    void r4_launchDaemons_alert() {
        // 서버가 macOS 에이전트에 내려주는 감시 경로는 세 곳이다(SensorConfig.DARWIN_WATCH_PATHS).
        // 판정에서 빠져 있으면 에이전트가 올린 이벤트를 그대로 버린다. root 로 도는 지속성 위치다.
        Event current = file("com.evil.daemon.plist",
                "/Library/LaunchDaemons/com.evil.daemon.plist", 4000, "CREATE");

        assertThat(Rules.evaluate(List.of(), current))
                .isPresent()
                .get()
                .extracting(Alert::ruleId)
                .isEqualTo("FILE_IN_AUTORUN_PATH");
    }

    @Test
    @DisplayName("R4 음성: 자동실행 경로에서 파일이 지워진 것은 지속성 확보가 아니다")
    void r4_deleteFromAutorunPath_noAlert() {
        // 삭제는 오히려 자동실행을 없애는 쪽이다. 앱 제거 때마다 지속성 알림이 나가면 그게 오탐이다.
        Event current = file("com.vendor.agent.plist",
                "/Users/victim/Library/LaunchAgents/com.vendor.agent.plist", 4000, "DELETE");

        assertThat(Rules.evaluate(List.of(), current)).isEmpty();
    }

    @Test
    @DisplayName("R4 양성: 생성·기록·이동은 자동실행이 실제로 등록되는 쪽이라 잡는다")
    void r4_createWriteRenameToAutorunPath_alert() {
        for (String action : List.of("CREATE", "WRITE", "RENAME")) {
            Event current = file("com.evil.agent.plist",
                    "/Users/victim/Library/LaunchAgents/com.evil.agent.plist", 4000, action);

            assertThat(Rules.evaluate(List.of(), current))
                    .as(action)
                    .isPresent()
                    .get()
                    .extracting(Alert::ruleId)
                    .isEqualTo("FILE_IN_AUTORUN_PATH");
        }
    }

    @Test
    @DisplayName("R4 양성: action 을 못 본 file 이벤트는 그대로 판정한다")
    void r4_missingAction_stillAlerts() {
        // 관측 못 한 값으로 탐지를 깎으면 action 을 안 싣는 수집 경로에서 R4 가 통째로 죽는다.
        Event current = file("com.evil.agent.plist",
                "/Users/victim/Library/LaunchAgents/com.evil.agent.plist", 4000);

        assertThat(Rules.evaluate(List.of(), current))
                .isPresent()
                .get()
                .extracting(Alert::ruleId)
                .isEqualTo("FILE_IN_AUTORUN_PATH");
    }

    @Test
    @DisplayName("R4 음성: 앱 번들 안의 LaunchAgents 는 자동실행 경로가 아니다")
    void r4_launchAgentsInsideAppBundle_noAlert() {
        // 앱 번들은 자기 Contents/Library/LaunchAgents 에 plist 원본을 넣어 배포한다.
        // 거기 파일이 생기는 것은 설치일 뿐이고, 실제 등록은 위 세 곳에 놓일 때 일어난다.
        Event current = file("com.vendor.agent.plist",
                "/Applications/Vendor.app/Contents/Library/LaunchAgents/com.vendor.agent.plist", 4000);

        assertThat(Rules.evaluate(List.of(), current)).isEmpty();
    }

    @Test
    @DisplayName("R5: 낡은 TLS 로 맺은 핸드셰이크 → WEAK_TLS_HANDSHAKE(T1573, MEDIUM, notify)")
    void r5_weakTlsHandshake_alerts() {
        Optional<Alert> alert = Rules.evaluate(List.of(), l7("evil.example.com", "TLS 1.0", 5000));

        assertThat(alert).isPresent();
        Alert a = alert.get();
        assertThat(a.ruleId()).isEqualTo("WEAK_TLS_HANDSHAKE");
        assertThat(a.mitre()).isEqualTo("T1573");
        assertThat(a.severity()).isEqualTo(Alert.SEV_MEDIUM);
        assertThat(a.action()).isEqualTo(Alert.ACTION_NOTIFY);
        assertThat(a.ts()).isEqualTo(5000);
        assertThat(a.tenantId()).isEqualTo(TENANT);
        // 요약은 api-service 가 원본 이벤트를 되찾는 판별자다(SourceEventMatcher).
        assertThat(a.matched()).containsExactly("l7 evil.example.com (TLS 1.0)");
        assertThat(a.domain()).isEqualTo("evil.example.com");
        assertThat(a.destIp()).isEqualTo("203.0.113.9");
    }

    @Test
    @DisplayName("R5 양성: SSL 3.0 과 TLS 1.1 도 낡은 버전이다")
    void r5_otherWeakVersions_alert() {
        for (String version : List.of("SSL 3.0", "TLS 1.1")) {
            assertThat(Rules.evaluate(List.of(), l7("evil.example.com", version, 5000)))
                    .as(version)
                    .isPresent()
                    .get()
                    .extracting(Alert::ruleId)
                    .isEqualTo("WEAK_TLS_HANDSHAKE");
        }
    }

    @Test
    @DisplayName("R5 음성: 지금 쓰는 버전은 미판정 (실기기 관측 624건이 전부 TLS 1.3 이었다)")
    void r5_currentTlsVersions_noAlert() {
        for (String version : List.of("TLS 1.2", "TLS 1.3")) {
            assertThat(Rules.evaluate(List.of(), l7("api.github.com", version, 5000)))
                    .as(version)
                    .isEmpty();
        }
    }

    @Test
    @DisplayName("R5 음성: tlsVersion 을 못 봤으면 발화하지 않는다")
    void r5_missingTlsVersion_noAlert() {
        // 관측 못 한 값을 낡은 버전으로 칠 수는 없다. 그러면 센서가 값을 못 싣는 구간이 통째로 알림이 된다.
        assertThat(Rules.evaluate(List.of(), l7("api.github.com", null, 5000))).isEmpty();
    }

    @Test
    @DisplayName("두 룰 동시 매칭 시 더 심각한 CRITICAL(R2) 채택")
    void bothMatch_pickMostSevere() {
        List<Event> buffer = List.of(
                process("winword.exe", "explorer.exe", 900),
                network("203.0.113.9", 443, 1000)
        );
        Event current = TestEvents.of(HOST, EventTypes.PROCESS, 2000, "powershell.exe", "winword.exe",
                "C:\\Users\\me\\Downloads\\payload.ps1", null, 0, null, null, null, TENANT);

        Optional<Alert> alert = Rules.evaluate(buffer, current);

        assertThat(alert).isPresent();
        assertThat(alert.get().severity()).isEqualTo(Alert.SEV_CRITICAL);
        assertThat(alert.get().ruleId()).isEqualTo("DOWNLOAD_AND_EXECUTE");
    }

    @Test
    @DisplayName("R2 음성: network 이벤트는 트리거가 아니다 (판정은 실행 쪽에서만 완성된다)")
    void r2_networkIsNotTrigger_noAlert() {
        // 네트워크 이벤트는 연결이 끝난 뒤에 기록되고 전송기가 묶어 보내므로 항상 늦게 도착한다.
        // 그 조합이 잡히는지는 이제 워터마크가 보장한다. 늦게 온 네트워크는 버퍼에 쌓이기만 하고
        // 판정은 실행 쪽 트리거에서만 완성된다. 양쪽에서 다 판정하면 같은 공격에 알림이 두 번 나간다.
        // 실기기 발화 확인(다운로드 경로 실행 + 5분 안의 443 접속)은 토폴로지 테스트가 이어받았다:
        // DetectionTopologyTest.downloadExecute_networkArrivesLate_emitsAlert
        List<Event> buffer = List.of(processFrom("evil", "/Users/me/Downloads/evil", 2000));

        assertThat(Rules.evaluate(buffer, network("203.0.113.9", 443, 1000))).isEmpty();
    }

    @Test
    @DisplayName("R2: 짝이 여럿이면 시각상 가장 가까운 다운로드를 근거로 쓴다")
    void r2_picksNearestPrecedingDownload() {
        // 아무 짝이나 쓰면 분석 화면에 엉뚱한 목적지가 뜬다. 판정 여부는 같아도 근거가 틀린다.
        List<Event> buffer = List.of(
                network("198.51.100.1", 443, 1000),
                network("203.0.113.9", 443, 1900));
        Event current = processFrom("evil", "/Users/me/Downloads/evil", 2000);

        Alert alert = Rules.evaluate(buffer, current).orElseThrow();

        assertThat(alert.destIp()).isEqualTo("203.0.113.9");
        assertThat(alert.matched()).first().asString().contains("203.0.113.9");
    }

    @Test
    @DisplayName("R1: 짝이 여럿이면 시각상 가장 가까운 office 실행을 근거로 쓴다")
    void r1_picksNearestPrecedingOfficeExec() {
        List<Event> buffer = List.of(
                process("winword.exe", "explorer.exe", 1000),
                process("winword.exe", "finder", 1900));
        Event current = process("powershell.exe", "winword.exe", 2000);

        Alert alert = Rules.evaluate(buffer, current).orElseThrow();

        assertThat(alert.matched()).first().asString().contains("parent finder");
    }

    @Test
    @DisplayName("시퀀스 트리거 판정: 시퀀스 룰을 완성시킬 수 있는 이벤트만 대기 큐에 넣는다")
    void isSequenceTrigger_onlySequenceCompletingEvents() {
        // 대기 큐에 노이즈까지 담으면 grace period 동안 상태가 부풀고 판정이 느려진다.
        assertThat(Rules.isSequenceTrigger(process("powershell.exe", "winword.exe", 1000))).isTrue();
        assertThat(Rules.isSequenceTrigger(processFrom("evil", "/tmp/evil", 1000))).isTrue();

        assertThat(Rules.isSequenceTrigger(network("203.0.113.9", 443, 1000))).isFalse();
        assertThat(Rules.isSequenceTrigger(process("powershell.exe", "explorer.exe", 1000))).isFalse();
        assertThat(Rules.isSequenceTrigger(process("onedrive.exe", "winword.exe", 1000))).isFalse();
        assertThat(Rules.isSequenceTrigger(script("zsh", "/bin/zsh /tmp/evil.sh", 1000))).isFalse();
        assertThat(Rules.isSequenceTrigger(null)).isFalse();
    }

    @Test
    @DisplayName("R2 음성: 네트워크가 먼저 도착해도 그것이 실행보다 나중에 일어났으면 판정하지 않는다")
    void r2_networkArrivesFirstButHappenedLater_noAlert() {
        // 도착 순서(D→E)와 발생 순서(E→D)가 어긋나는 경우다. 도착 순서로 판정하면 여기서 오탐이 난다.
        // 반대 도착 순서는 r2_executeBeforeDownload_noAlert 가 덮는다. 둘 다 있어야 시각 판정이 지켜진다.
        List<Event> buffer = List.of(network("203.0.113.9", 443, 2000));
        Event earlierExec = processFrom("evil", "/Users/me/Downloads/evil", 1000);

        assertThat(Rules.evaluate(buffer, earlierExec)).isEmpty();
    }

    @Test
    @DisplayName("CRITICAL 권고는 kill 이다 (격리는 구현이 없어 권고하지 않는다)")
    void criticalRecommendsKill() {
        // 권고와 실제 조치가 다르면 사용자가 격리된 줄 알고 넘어간다.
        // responder 가 할 수 있는 건 프로세스 종료뿐이라 권고도 거기에 맞춘다.
        assertThat(Alert.actionFor(Alert.SEV_CRITICAL)).isEqualTo(Alert.ACTION_KILL);
        assertThat(Alert.actionFor(Alert.SEV_HIGH)).isEqualTo(Alert.ACTION_KILL);
        assertThat(Alert.actionFor(Alert.SEV_MEDIUM)).isEqualTo(Alert.ACTION_NOTIFY);
    }
}
