package com.edrdog.detectorservice.rule;

import com.edrdog.detectorservice.dto.Alert;
import com.edrdog.detectorservice.dto.Event;
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
        return new Event(HOST, Event.TYPE_PROCESS, ts, proc, parent, proc + " args", null, 0, TENANT);
    }

    /** cmdline 을 직접 주는 process 이벤트. R2 는 실행 경로(cmdline)를 본다. */
    private Event processFrom(String proc, String cmdline, long ts) {
        return new Event(HOST, Event.TYPE_PROCESS, ts, proc, "bash", cmdline, null, 0, TENANT);
    }

    private Event network(String destIp, int destPort, long ts) {
        return new Event(HOST, Event.TYPE_NETWORK, ts, null, null, null, destIp, destPort, TENANT);
    }

    private Event script(String proc, String fullCmdline, long ts) {
        return new Event(HOST, Event.TYPE_SCRIPT, ts, proc, "explorer.exe", fullCmdline, null, 0, TENANT);
    }

    private Event file(String name, String fullPath, long ts) {
        return new Event(HOST, Event.TYPE_FILE, ts, name, null, fullPath, null, 0, TENANT);
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
    @DisplayName("R3 양성: 인터프리터가 임시 경로 스크립트를 인자로 실행하면 잡는다")
    void r3_interpreterRunsTempScript_alerts() {
        Event current = script("zsh", "/bin/zsh /tmp/evil.sh", 3000);

        Optional<Alert> alert = Rules.evaluate(List.of(), current);

        assertThat(alert).isPresent();
        assertThat(alert.get().ruleId()).isEqualTo("SCRIPT_FROM_TEMP_PATH");
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
    @DisplayName("두 룰 동시 매칭 시 더 심각한 CRITICAL(R2) 채택")
    void bothMatch_pickMostSevere() {
        List<Event> buffer = List.of(
                process("winword.exe", "explorer.exe", 900),
                network("203.0.113.9", 443, 1000)
        );
        Event current = new Event(HOST, Event.TYPE_PROCESS, 2000, "powershell.exe", "winword.exe",
                "C:\\Users\\me\\Downloads\\payload.ps1", null, 0, TENANT);

        Optional<Alert> alert = Rules.evaluate(buffer, current);

        assertThat(alert).isPresent();
        assertThat(alert.get().severity()).isEqualTo(Alert.SEV_CRITICAL);
        assertThat(alert.get().ruleId()).isEqualTo("DOWNLOAD_AND_EXECUTE");
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
