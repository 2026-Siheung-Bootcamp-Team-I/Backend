package com.edrdog.responderservice.response;

import com.edrdog.responderservice.fleet.FleetScriptResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Fleet 스크립트 실행 결과(exit_code/host_timeout/output)를 조치 결과로 해석하는 순수 로직 검증.
 */
class KillOutcomeTest {

    private FleetScriptResult result(Integer exitCode, boolean hostTimeout, String output) {
        return new FleetScriptResult("exec-1", exitCode, hostTimeout, output, "");
    }

    @Test
    @DisplayName("exit 0 + KILLED 마커면 KILLED")
    void killed() {
        var r = result(0, false, "EDRDOG_RESULT=MATCH name=x pids=42\nEDRDOG_RESULT=KILLED name=x pids=42");
        assertThat(KillOutcome.interpret(r)).isEqualTo(KillOutcome.KILLED);
    }

    @Test
    @DisplayName("exit 0 + NO_MATCH 마커면 NO_MATCH")
    void noMatch() {
        var r = result(0, false, "EDRDOG_RESULT=NO_MATCH name=x");
        assertThat(KillOutcome.interpret(r)).isEqualTo(KillOutcome.NO_MATCH);
    }

    @Test
    @DisplayName("host_timeout 이면 exit_code 와 무관하게 TIMEOUT")
    void hostTimeout() {
        assertThat(KillOutcome.interpret(result(null, true, ""))).isEqualTo(KillOutcome.TIMEOUT);
    }

    @Test
    @DisplayName("exit_code 가 아직 없으면(비동기 대기) TIMEOUT 으로 간주")
    void pendingExitCode() {
        assertThat(KillOutcome.interpret(result(null, false, ""))).isEqualTo(KillOutcome.TIMEOUT);
    }

    @Test
    @DisplayName("0 아닌 exit_code 는 FAILED")
    void nonZeroExit() {
        assertThat(KillOutcome.interpret(result(1, false, "some error"))).isEqualTo(KillOutcome.FAILED);
    }

    @Test
    @DisplayName("exit 0 인데 마커가 없으면 FAILED(예상치 못한 출력)")
    void exitZeroNoMarker() {
        assertThat(KillOutcome.interpret(result(0, false, "garbage"))).isEqualTo(KillOutcome.FAILED);
    }
}
