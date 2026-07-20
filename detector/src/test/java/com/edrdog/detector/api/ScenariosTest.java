package com.edrdog.detector.api;

import com.edrdog.detector.dto.Alert;
import com.edrdog.detector.dto.Event;
import com.edrdog.detector.rule.Rules;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * 시나리오가 실제로 룰을 트리거하는지 검증 (Rules 로 직접 판정).
 * 시퀀스의 마지막 이벤트가 트리거이며, 선행 이벤트를 버퍼로 넣어 평가한다.
 */
class ScenariosTest {

    private static final String HOST = "demo-host-01";

    /** 마지막 이벤트를 current, 나머지를 prior 버퍼로 넣어 판정. */
    private static Optional<Alert> detect(List<Event> events) {
        List<Event> prior = events.subList(0, events.size() - 1);
        Event current = events.get(events.size() - 1);
        return Rules.evaluate(prior, current);
    }

    @Test
    void process_chain_시나리오는_T1059_HIGH_를_트리거한다() {
        List<Event> events = Scenarios.build(Scenarios.PROCESS_CHAIN, HOST, 1_000_000L);

        Optional<Alert> alert = detect(events);

        assertThat(alert).isPresent();
        assertThat(alert.get().ruleId()).isEqualTo("SUSPICIOUS_PROCESS_CHAIN");
        assertThat(alert.get().mitre()).isEqualTo("T1059");
        assertThat(alert.get().severity()).isEqualTo(Alert.SEV_HIGH);
        assertThat(alert.get().action()).isEqualTo(Alert.ACTION_KILL);
        assertThat(alert.get().host()).isEqualTo(HOST);
    }

    @Test
    void download_exec_시나리오는_T1105_CRITICAL_을_트리거한다() {
        List<Event> events = Scenarios.build(Scenarios.DOWNLOAD_EXEC, HOST, 1_000_000L);

        Optional<Alert> alert = detect(events);

        assertThat(alert).isPresent();
        assertThat(alert.get().ruleId()).isEqualTo("DOWNLOAD_AND_EXECUTE");
        assertThat(alert.get().severity()).isEqualTo(Alert.SEV_CRITICAL);
        assertThat(alert.get().action()).isEqualTo(Alert.ACTION_ISOLATE);
    }

    @Test
    void 두_이벤트는_같은_host_와_윈도우_안_순서를_가진다() {
        List<Event> events = Scenarios.build(Scenarios.PROCESS_CHAIN, HOST, 1_000_000L);

        assertThat(events).hasSize(2);
        assertThat(events).allMatch(e -> HOST.equals(e.host()));
        assertThat(events.get(1).ts() - events.get(0).ts()).isEqualTo(1000L);
    }

    @Test
    void 미지원_시나리오는_예외() {
        assertThatThrownBy(() -> Scenarios.build("nope", HOST, 0L))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
