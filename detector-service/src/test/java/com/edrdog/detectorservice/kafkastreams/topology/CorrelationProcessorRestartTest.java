package com.edrdog.detectorservice.kafkastreams.topology;

import com.edrdog.detectorservice.dto.Alert;
import com.edrdog.detectorservice.kafkastreams.serde.EventBufferSerde;
import com.edrdog.detectorservice.support.TestEvents;
import com.edrdog.schema.Event;
import com.edrdog.schema.EventTypes;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.apache.kafka.common.serialization.Serdes;
import org.apache.kafka.streams.processor.PunctuationType;
import org.apache.kafka.streams.processor.api.MockProcessorContext;
import org.apache.kafka.streams.processor.api.Record;
import org.apache.kafka.streams.state.KeyValueStore;
import org.apache.kafka.streams.state.Stores;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 프로세서를 새로 만들었을 때(재시작·리밸런싱) 대기 중이던 트리거가 그대로 판정되는지 검증.
 *
 * <p>punctuate 가 보는 후보 목록(pendingHosts)은 프로세서 메모리에 있다. 그래서 프로세서가 새로 생기면
 * init() 이 state store 를 훑어 복원해야 하고, 그게 안 되면 재시작 직전 대기 중이던 트리거가
 * 단말이 다시 이벤트를 보낼 때까지 — 꺼졌다면 영영 — 판정되지 않는다. 여기서 막는다.
 *
 * <p>TopologyTestDriver 로는 이 시나리오를 못 만든다. driver.close() 가 상태 디렉터리를 지우고,
 * 드라이버 안의 프로세서 인스턴스를 다시 init 할 방법도 없다. 그래서 프로세서를 직접 돌린다.
 * store 는 값을 바이트로 들고 있어(serde 왕복) 복원된 상태를 읽는 상황과 같다.
 */
class CorrelationProcessorRestartTest {

    private static final long WINDOW_MS = DetectionTopology.WINDOW_MS;
    private static final long GRACE_MS = DetectionTopology.GRACE_MS;

    private MockProcessorContext<String, Alert> ctx;
    private KeyValueStore<String, EventBuffer> store;

    @BeforeEach
    void setUp() {
        ctx = new MockProcessorContext<>();
        store = Stores.keyValueStoreBuilder(
                        Stores.inMemoryKeyValueStore(CorrelationProcessor.STORE),
                        Serdes.String(),
                        new EventBufferSerde())
                .withLoggingDisabled()
                .build();
        store.init(ctx.getStateStoreContext(), store);
        ctx.addStateStore(store);
        ctx.setCurrentSystemTimeMs(10_000);
    }

    @AfterEach
    void tearDown() {
        store.close();
    }

    /** 새 프로세서를 붙인다. 재시작하면 실제로 이 일이 일어난다. */
    private CorrelationProcessor startProcessor() {
        CorrelationProcessor processor = new CorrelationProcessor(WINDOW_MS, GRACE_MS, new SimpleMeterRegistry());
        processor.init(ctx);
        return processor;
    }

    /** 마지막으로 붙은 프로세서가 등록한 punctuator 를 돌린다. */
    private void punctuate(long nowWallMs) {
        ctx.setCurrentSystemTimeMs(nowWallMs);
        var punctuators = ctx.scheduledPunctuators();
        var last = punctuators.get(punctuators.size() - 1);
        assertThat(last.getType()).isEqualTo(PunctuationType.WALL_CLOCK_TIME);
        last.getPunctuator().punctuate(nowWallMs);
    }

    private static Event process(String host, String proc, String parent, long ts) {
        return TestEvents.of(host, EventTypes.PROCESS, ts, proc, parent, proc, null, 0, null, null, null, "tenant-a");
    }

    private List<String> forwardedRules() {
        return ctx.forwarded().stream().map(f -> f.record().value().ruleId()).toList();
    }

    @Test
    @DisplayName("재시작해도 대기 중이던 트리거는 grace 후 판정된다")
    void pendingSurvivesRestart() {
        CorrelationProcessor before = startProcessor();
        before.process(new Record<>("host-1", process("host-1", "winword.exe", "explorer.exe", 1000), 1000));
        before.process(new Record<>("host-1", process("host-1", "powershell.exe", "winword.exe", 2000), 2000));
        assertThat(ctx.forwarded()).isEmpty();   // 아직 워터마크 전이라 대기 중이어야 한다
        before.close();

        // 재시작: 새 프로세서가 붙고, 남아 있는 state store 만으로 대기 목록을 되찾아야 한다
        startProcessor();
        punctuate(10_000 + GRACE_MS * 2);

        assertThat(forwardedRules()).containsExactly("SUSPICIOUS_PROCESS_CHAIN");
    }

    @Test
    @DisplayName("재시작 후에도 같은 트리거를 두 번 판정하지 않는다")
    void restoredPendingIsEvaluatedOnce() {
        // 중복 발행되면 responder 가 같은 프로세스에 kill 을 여러 번 쏜다.
        CorrelationProcessor before = startProcessor();
        before.process(new Record<>("host-1", process("host-1", "winword.exe", "explorer.exe", 1000), 1000));
        before.process(new Record<>("host-1", process("host-1", "powershell.exe", "winword.exe", 2000), 2000));
        before.close();

        startProcessor();
        punctuate(10_000 + GRACE_MS * 2);
        punctuate(10_000 + GRACE_MS * 4);

        assertThat(forwardedRules()).containsExactly("SUSPICIOUS_PROCESS_CHAIN");
    }

    @Test
    @DisplayName("대기 트리거가 없는 host 는 복원 대상이 아니라 punctuate 가 아무것도 하지 않는다")
    void hostWithoutPendingIsNotRestored() {
        // 선행 근거만 쌓인 host 는 store 에 남지만 판정할 것이 없다. 여기서 알림이 나오면 오탐이다.
        CorrelationProcessor before = startProcessor();
        before.process(new Record<>("host-2", process("host-2", "winword.exe", "explorer.exe", 1000), 1000));
        before.close();
        assertThat(store.get("host-2")).isNotNull();

        startProcessor();
        punctuate(10_000 + GRACE_MS * 4);

        assertThat(ctx.forwarded()).isEmpty();
    }
}
