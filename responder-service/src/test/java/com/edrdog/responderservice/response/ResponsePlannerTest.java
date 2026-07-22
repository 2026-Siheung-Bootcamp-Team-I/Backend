package com.edrdog.responderservice.response;

import com.edrdog.responderservice.dto.Alert;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** alert → dry-run 조치 텍스트 매핑과 쿨다운 억제 검증 (순수 로직). */
class ResponsePlannerTest {

    private Alert alert(String host, String ruleId, String action, long ts) {
        return new Alert(host, ruleId, "T1059", "HIGH", action, ts, List.of("evidence"));
    }

    @Test
    @DisplayName("kill 은 프로세스 종료 권장 텍스트로, trigger=response 태깅되어 표시")
    void kill_mapsToText() {
        ResponsePlanner planner = new ResponsePlanner(60_000);
        String line = planner.plan(alert("host-1", "SUSPICIOUS_PROCESS_CHAIN", Alert.ACTION_KILL, 1_000)).orElseThrow();

        assertThat(line).contains("trigger=response");
        assertThat(line).contains("host=host-1");
        assertThat(line).contains("action=kill");
        assertThat(line).contains("프로세스 종료 권장");
    }

    @Test
    @DisplayName("isolate 는 호스트 격리 권장 텍스트로 표시")
    void isolate_mapsToText() {
        ResponsePlanner planner = new ResponsePlanner(60_000);
        String line = planner.plan(alert("host-2", "DOWNLOAD_AND_EXECUTE", Alert.ACTION_ISOLATE, 1_000)).orElseThrow();

        assertThat(line).contains("action=isolate");
        assertThat(line).contains("호스트 격리 권장");
    }

    @Test
    @DisplayName("같은 host+action 이 쿨다운 안에 다시 오면 표시 안 함")
    void sameHostAction_withinCooldown_suppressed() {
        ResponsePlanner planner = new ResponsePlanner(60_000);
        planner.plan(alert("host-1", "R", Alert.ACTION_KILL, 1_000));

        assertThat(planner.plan(alert("host-1", "R", Alert.ACTION_KILL, 30_000))).isEmpty();
    }

    @Test
    @DisplayName("같은 host 라도 action 이 다르면 각각 표시")
    void sameHost_differentAction_shown() {
        ResponsePlanner planner = new ResponsePlanner(60_000);
        planner.plan(alert("host-1", "R", Alert.ACTION_KILL, 1_000));

        assertThat(planner.plan(alert("host-1", "R", Alert.ACTION_ISOLATE, 1_000))).isPresent();
    }
}
