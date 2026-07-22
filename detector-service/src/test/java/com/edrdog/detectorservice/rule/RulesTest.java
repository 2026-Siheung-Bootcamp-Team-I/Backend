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

    private Event process(String proc, String parent, long ts) {
        return new Event(HOST, Event.TYPE_PROCESS, ts, proc, parent, proc + " args", null, 0);
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
}
