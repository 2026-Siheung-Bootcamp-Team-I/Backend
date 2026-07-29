package com.edrdog.responderservice.response;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** 에이전트가 보고한 문자열을 알려진 상태로 해석하는 순수 로직 검증. */
class KillOutcomeTest {

    @Test
    @DisplayName("에이전트가 쓰는 세 상태는 그대로 해석한다")
    void knownStatuses() {
        assertThat(KillOutcome.of("KILLED")).isEqualTo(KillOutcome.KILLED);
        assertThat(KillOutcome.of("NO_MATCH")).isEqualTo(KillOutcome.NO_MATCH);
        assertThat(KillOutcome.of("FAILED")).isEqualTo(KillOutcome.FAILED);
    }

    @Test
    @DisplayName("모르는 문자열은 FAILED (엔드포인트가 보낸 값을 그대로 믿지 않는다)")
    void unknownStatus() {
        assertThat(KillOutcome.of("KILLED_MAYBE")).isEqualTo(KillOutcome.FAILED);
        assertThat(KillOutcome.of("killed")).isEqualTo(KillOutcome.FAILED);
        assertThat(KillOutcome.of("")).isEqualTo(KillOutcome.FAILED);
    }

    @Test
    @DisplayName("서버가 붙이는 상태는 에이전트가 보고할 수 없다")
    void serverOnlyStatusesAreRejected() {
        assertThat(KillOutcome.of("TIMEOUT")).isEqualTo(KillOutcome.FAILED);
        assertThat(KillOutcome.of("COOLDOWN")).isEqualTo(KillOutcome.FAILED);
        assertThat(KillOutcome.of("DISABLED")).isEqualTo(KillOutcome.FAILED);
    }

    @Test
    @DisplayName("null 은 FAILED")
    void nullStatus() {
        assertThat(KillOutcome.of(null)).isEqualTo(KillOutcome.FAILED);
    }
}
