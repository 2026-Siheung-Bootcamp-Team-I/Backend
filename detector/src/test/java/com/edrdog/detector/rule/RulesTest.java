package com.edrdog.detector.rule;

import com.edrdog.detector.dto.Alert;
import com.edrdog.detector.dto.Event;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/** 상관분석 룰 판정 순수 로직 테스트. 버퍼는 이미 윈도우로 정리됐다고 가정(윈도우 판정은 프로세서 책임). */
class RulesTest {

    private static final String HOST = "host-1";

    private Event process(String proc, String parent, long ts) {
        return new Event(HOST, Event.TYPE_PROCESS, ts, proc, parent, proc + " args", null, 0);
    }

    private Event process(String proc, String parent, String cmdline, long ts) {
        return new Event(HOST, Event.TYPE_PROCESS, ts, proc, parent, cmdline, null, 0);
    }

    private Event network(String destIp, int destPort, long ts) {
        return new Event(HOST, Event.TYPE_NETWORK, ts, null, null, null, destIp, destPort);
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
    }

    @Test
    @DisplayName("R1 음성: shell 이지만 부모가 office앱(또는 시스템 프로세스)이 아니면 미판정")
    void r1_shellWithNonOfficeParent_noAlert() {
        List<Event> buffer = List.of(process("userinit.exe", "winlogon.exe", 1000));
        Event current = process("powershell.exe", "userinit.exe", 2000);

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
    @DisplayName("R2: network 다운로드 후 같은 host 에서 process 실행 → DOWNLOAD_AND_EXECUTE(T1105+T1204, CRITICAL, isolate)")
    void r2_downloadThenExecute_alerts() {
        List<Event> buffer = List.of(network("203.0.113.9", 443, 1000));
        Event current = process("evil.exe", "cmd.exe", 2000);

        Optional<Alert> alert = Rules.evaluate(buffer, current);

        assertThat(alert).isPresent();
        Alert a = alert.get();
        assertThat(a.ruleId()).isEqualTo("DOWNLOAD_AND_EXECUTE");
        assertThat(a.mitre()).isEqualTo("T1105+T1204");
        assertThat(a.severity()).isEqualTo(Alert.SEV_CRITICAL);
        assertThat(a.action()).isEqualTo(Alert.ACTION_ISOLATE);
        assertThat(a.ts()).isEqualTo(2000);
        assertThat(a.matched()).hasSize(2);
        assertThat(a.destIp()).isEqualTo("203.0.113.9");
        assertThat(a.destPort()).isEqualTo(443);
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
    @DisplayName("두 룰 동시 매칭 시 더 심각한 CRITICAL(R2) 채택")
    void bothMatch_pickMostSevere() {
        List<Event> buffer = List.of(
                process("winword.exe", "explorer.exe", 900),
                network("203.0.113.9", 443, 1000)
        );
        Event current = process("powershell.exe", "winword.exe", 2000);

        Optional<Alert> alert = Rules.evaluate(buffer, current);

        assertThat(alert).isPresent();
        assertThat(alert.get().severity()).isEqualTo(Alert.SEV_CRITICAL);
        assertThat(alert.get().ruleId()).isEqualTo("DOWNLOAD_AND_EXECUTE");
    }

    // --- ENCODED_POWERSHELL (T1059.001, HIGH) ---

    @Test
    @DisplayName("ENCODED_POWERSHELL: powershell -enc 인코딩 명령 → T1059.001, HIGH, kill")
    void encodedPowershell_encFlag_alerts() {
        Event current = process("powershell.exe", "cmd.exe",
                "powershell.exe -nop -w hidden -enc SQBFAFgA", 2000);

        Optional<Alert> alert = Rules.evaluate(List.of(), current);

        assertThat(alert).isPresent();
        Alert a = alert.get();
        assertThat(a.ruleId()).isEqualTo("ENCODED_POWERSHELL");
        assertThat(a.mitre()).isEqualTo("T1059.001");
        assertThat(a.severity()).isEqualTo(Alert.SEV_HIGH);
        assertThat(a.action()).isEqualTo(Alert.ACTION_KILL);
        assertThat(a.destIp()).isEmpty();
        assertThat(a.destPort()).isZero();
    }

    @Test
    @DisplayName("ENCODED_POWERSHELL 음성: 인코딩 플래그/blob 없는 평범한 powershell 명령은 미판정")
    void encodedPowershell_plainCommand_noAlert() {
        Event current = process("powershell.exe", "cmd.exe", "powershell.exe Get-Process", 2000);

        assertThat(Rules.evaluate(List.of(), current)).isEmpty();
    }

    // --- LSASS_ACCESS (T1003.001, CRITICAL) ---

    @Test
    @DisplayName("LSASS_ACCESS: comsvcs 로 lsass 덤프 → T1003.001, CRITICAL, isolate")
    void lsassAccess_comsvcsDump_alerts() {
        Event current = process("rundll32.exe", "cmd.exe",
                "rundll32.exe comsvcs.dll, MiniDump 624 lsass.dmp full", 2000);

        Optional<Alert> alert = Rules.evaluate(List.of(), current);

        assertThat(alert).isPresent();
        Alert a = alert.get();
        assertThat(a.ruleId()).isEqualTo("LSASS_ACCESS");
        assertThat(a.mitre()).isEqualTo("T1003.001");
        assertThat(a.severity()).isEqualTo(Alert.SEV_CRITICAL);
        assertThat(a.action()).isEqualTo(Alert.ACTION_ISOLATE);
        assertThat(a.destIp()).isEmpty();
    }

    @Test
    @DisplayName("LSASS_ACCESS 음성: lsass 언급만 있고 덤프 도구 없으면 미판정")
    void lsassAccess_mentionOnly_noAlert() {
        Event current = process("cmd.exe", "userinit.exe", "cmd.exe /c echo lsass is running", 2000);

        assertThat(Rules.evaluate(List.of(), current)).isEmpty();
    }

    // --- C2_BEACONING (T1071, HIGH) ---

    @Test
    @DisplayName("C2_BEACONING: 같은 목적지로 3회째 연결 → T1071, HIGH, destIp 채움")
    void c2Beaconing_thirdConnection_alerts() {
        List<Event> buffer = List.of(
                network("198.51.100.7", 443, 1000),
                network("198.51.100.7", 443, 1500)
        );
        Event current = network("198.51.100.7", 443, 2000);

        Optional<Alert> alert = Rules.evaluate(buffer, current);

        assertThat(alert).isPresent();
        Alert a = alert.get();
        assertThat(a.ruleId()).isEqualTo("C2_BEACONING");
        assertThat(a.mitre()).isEqualTo("T1071");
        assertThat(a.severity()).isEqualTo(Alert.SEV_HIGH);
        assertThat(a.destIp()).isEqualTo("198.51.100.7");
        assertThat(a.destPort()).isEqualTo(443);
    }

    @Test
    @DisplayName("C2_BEACONING 음성: 같은 목적지 연결이 2회뿐이면(임계치 미달) 미판정")
    void c2Beaconing_onlyTwo_noAlert() {
        List<Event> buffer = List.of(network("198.51.100.7", 443, 1000));
        Event current = network("198.51.100.7", 443, 2000);

        assertThat(Rules.evaluate(buffer, current)).isEmpty();
    }

    // --- SUSPICIOUS_PARENT_CHILD (T1055, HIGH) ---

    @Test
    @DisplayName("SUSPICIOUS_PARENT_CHILD: services.exe 가 cmd.exe 를 자식으로 실행 → T1055, HIGH")
    void suspiciousParentChild_servicesSpawnsShell_alerts() {
        Event current = process("cmd.exe", "services.exe", 2000);

        Optional<Alert> alert = Rules.evaluate(List.of(), current);

        assertThat(alert).isPresent();
        Alert a = alert.get();
        assertThat(a.ruleId()).isEqualTo("SUSPICIOUS_PARENT_CHILD");
        assertThat(a.mitre()).isEqualTo("T1055");
        assertThat(a.severity()).isEqualTo(Alert.SEV_HIGH);
        assertThat(a.action()).isEqualTo(Alert.ACTION_KILL);
        assertThat(a.destIp()).isEmpty();
    }

    @Test
    @DisplayName("SUSPICIOUS_PARENT_CHILD 음성: 부모가 시스템 프로세스 집합이 아니면 미판정")
    void suspiciousParentChild_normalParent_noAlert() {
        Event current = process("cmd.exe", "userinit.exe", 2000);

        assertThat(Rules.evaluate(List.of(), current)).isEmpty();
    }

    @Test
    @DisplayName("SUSPICIOUS_PARENT_CHILD 음성: explorer.exe → cmd.exe 는 사용자 정상 동작이라 미판정")
    void suspiciousParentChild_explorerSpawnsShell_noAlert() {
        Event current = process("cmd.exe", "explorer.exe", 2000);

        assertThat(Rules.evaluate(List.of(), current)).isEmpty();
    }

    // --- DEFENSE_EVASION (T1562, CRITICAL) ---

    @Test
    @DisplayName("DEFENSE_EVASION: Windows Defender 서비스 중지 → T1562, CRITICAL, isolate")
    void defenseEvasion_stopsDefender_alerts() {
        Event current = process("cmd.exe", "explorer.exe", "cmd.exe /c sc stop WinDefend", 2000);

        Optional<Alert> alert = Rules.evaluate(List.of(), current);

        assertThat(alert).isPresent();
        Alert a = alert.get();
        assertThat(a.ruleId()).isEqualTo("DEFENSE_EVASION");
        assertThat(a.mitre()).isEqualTo("T1562");
        assertThat(a.severity()).isEqualTo(Alert.SEV_CRITICAL);
        assertThat(a.action()).isEqualTo(Alert.ACTION_ISOLATE);
        assertThat(a.destIp()).isEmpty();
    }

    @Test
    @DisplayName("DEFENSE_EVASION 음성: 방화벽 조회 등 무력화가 아닌 명령은 미판정")
    void defenseEvasion_benignFirewallQuery_noAlert() {
        Event current = process("cmd.exe", "userinit.exe", "cmd.exe /c netsh advfirewall show allprofiles", 2000);

        assertThat(Rules.evaluate(List.of(), current)).isEmpty();
    }
}
