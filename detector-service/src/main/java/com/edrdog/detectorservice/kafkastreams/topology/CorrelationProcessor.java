package com.edrdog.detectorservice.kafkastreams.topology;

import com.edrdog.detectorservice.dto.Alert;
import com.edrdog.schema.Event;
import com.edrdog.detectorservice.rule.Rules;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.MeterRegistry;
import org.apache.kafka.streams.KeyValue;
import org.apache.kafka.streams.processor.PunctuationType;
import org.apache.kafka.streams.processor.api.Processor;
import org.apache.kafka.streams.processor.api.ProcessorContext;
import org.apache.kafka.streams.processor.api.Record;
import org.apache.kafka.streams.state.KeyValueIterator;
import org.apache.kafka.streams.state.KeyValueStore;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * host(key) 별 이벤트 버퍼를 유지하며 시퀀스 상관분석을 수행.
 *
 * <p>버퍼는 이벤트 시각(ts) 오름차순으로 유지하고, 시퀀스 룰은 그 host 의 워터마크
 * (해당 host 의 maxTs - grace) 이후에 시각 순서대로 판정한다. 덕분에 도착 순서가 뒤섞여도 결과가 같다.
 * 점 룰(단일 이벤트)은 선행 근거가 필요 없어 기다리지 않고 즉시 판정한다.
 *
 * <p>워터마크가 host 별인 이유는 단말마다 전송 주기 위상이 달라서다. 전역 stream-time 을 쓰면
 * 방금 배치를 보낸 단말이 아직 주기가 안 된 단말의 이벤트를 전부 late 로 만들어, grace 를
 * 전송 주기만큼(현재 5초) 잡아야 한다. host 별로 두면 grace 는 단말 내부 어긋남만 덮으면 된다.
 */
public class CorrelationProcessor implements Processor<String, Event, String, Alert> {

    static final String STORE = "event-buffer";

    /** 워터마크 진행을 확인하는 주기. 짧을수록 판정이 빠르다. */
    static final long PUNCTUATE_INTERVAL_MS = 500;

    private final long windowMs;
    private final long graceMs;
    private final MeterRegistry metrics;
    private final DistributionSummary lateness;

    private KeyValueStore<String, EventBuffer> store;
    private ProcessorContext<String, Alert> ctx;

    /**
     * pending 이 남은 host → 그 host 의 마지막 갱신 시각(wall clock).
     * punctuate 가 볼 후보를 여기로 좁힌다. 이게 없으면 store 전체를 초당 두 번 역직렬화하며 훑어야 하고,
     * 비용이 단말 수에 정비례한다. 시퀀스 트리거는 드물어서 대부분 host 는 여기 없다.
     *
     * <p>메모리에만 두지만 대기 트리거를 잃지 않는다. 재시작·리밸런싱이면 프로세서가 새로 만들어지고
     * init() 이 store 를 한 번 훑어 복원한다 (Kafka Streams 는 상태 복원이 끝난 뒤에야 init() 을 부른다).
     */
    private final Map<String, Long> pendingHosts = new LinkedHashMap<>();

    public CorrelationProcessor(long windowMs, long graceMs, MeterRegistry metrics) {
        this.windowMs = windowMs;
        this.graceMs = graceMs;
        this.metrics = metrics;
        this.lateness = DistributionSummary.builder("cep.event.lateness")
                .description("이벤트가 같은 host 의 최신 이벤트 시각 대비 얼마나 뒤처져 도착했는지 — grace 값 산정 근거")
                .baseUnit("ms")
                .publishPercentiles(0.5, 0.95, 0.99)
                .register(metrics);
    }

    @Override
    public void init(ProcessorContext<String, Alert> context) {
        this.ctx = context;
        this.store = context.getStateStore(STORE);
        restorePendingHosts();
        context.schedule(Duration.ofMillis(PUNCTUATE_INTERVAL_MS), PunctuationType.WALL_CLOCK_TIME,
                this::flushQuietHosts);
    }

    /**
     * 복원된 state store 를 한 번만 훑어 pendingHosts 를 되살린다.
     * 이 스캔이 없으면 재시작 직전 대기 중이던 트리거는 그 host 가 다시 이벤트를 보낼 때까지,
     * 단말이 꺼졌다면 영영 판정되지 않는다. 태스크 할당당 한 번이라 punctuate 순회와 달리 누적되지 않는다.
     */
    private void restorePendingHosts() {
        pendingHosts.clear();
        try (KeyValueIterator<String, EventBuffer> it = store.all()) {
            while (it.hasNext()) {
                KeyValue<String, EventBuffer> kv = it.next();
                if (kv.value != null && !kv.value.pending.isEmpty()) {
                    pendingHosts.put(kv.key, kv.value.lastUpdatedWallMs);
                }
            }
        }
    }

    @Override
    public void process(Record<String, Event> record) {
        Event current = record.value();
        if (current == null || record.key() == null) {
            return;
        }
        String host = record.key();

        EventBuffer buffer = store.get(host);
        if (buffer == null) {
            buffer = new EventBuffer();
        }
        buffer.maxTs = Math.max(buffer.maxTs, current.getTs());
        buffer.lastUpdatedWallMs = ctx.currentSystemTimeMs();
        long watermark = buffer.maxTs - graceMs;
        lateness.record(Math.max(0, buffer.maxTs - current.getTs()));

        if (Rules.isSequenceTrigger(current)) {
            if (current.getTs() < watermark) {
                // 워터마크를 넘겨 도착 — 버리면 확정 미탐이라 이미 모인 근거로 그 자리에서 판정한다
                metrics.counter("cep.late.events", "type", current.getType()).increment();
                evaluate(host, buffer, current);
            } else {
                insertByTs(buffer.pending, current);
            }
        } else {
            // 점 룰은 선행 근거가 필요 없다. 기다리면 대응만 늦어진다
            Rules.evaluate(List.of(), current).ifPresent(alert -> forward(host, alert));
        }

        // 전부 담으면 상한(EventBuffer.MAX)이 금방 차서 5분 윈도우가 십여 초로 줄어든다.
        if (Rules.isCorrelatable(current)) {
            insertByTs(buffer.events, current);
        }
        flushPending(host, buffer, watermark);
        prune(buffer, watermark);
        save(host, buffer);
    }

    /** 워터마크를 넘긴 대기 트리거를 시각 순서대로 판정한다. */
    private void flushPending(String host, EventBuffer buffer, long watermark) {
        while (!buffer.pending.isEmpty()
                && (buffer.pending.get(0).getTs() <= watermark || buffer.pending.size() > EventBuffer.MAX_PENDING)) {
            evaluate(host, buffer, buffer.pending.remove(0));
        }
    }

    private void evaluate(String host, EventBuffer buffer, Event trigger) {
        Rules.evaluate(priorOf(buffer, trigger), trigger).ifPresent(alert -> forward(host, alert));
    }

    /** 트리거 이전 윈도우 안의 선행 이벤트만 정렬된 채로 넘긴다 (Rules 의 prior 계약). */
    private List<Event> priorOf(EventBuffer buffer, Event trigger) {
        List<Event> prior = new ArrayList<>();
        for (Event e : buffer.events) {
            if (e.getTs() > trigger.getTs()) {
                break;   // 정렬돼 있으니 여기부터는 볼 필요가 없다
            }
            // 트리거가 근거 후보이기도 하면 자기 자신과 상관될 수 있어 뺀다
            if (e.getTs() >= trigger.getTs() - windowMs && !e.equals(trigger)) {
                prior.add(e);
            }
        }
        return prior;
    }

    /** 윈도우 밖 선행 이벤트 제거와 상한 유지. 둘 다 이벤트 시각 기준이라 도착 순서에 흔들리지 않는다. */
    private void prune(EventBuffer buffer, long watermark) {
        long floor = watermark - windowMs;
        while (!buffer.events.isEmpty() && buffer.events.get(0).getTs() < floor) {
            buffer.events.remove(0);
        }
        while (buffer.events.size() > EventBuffer.MAX) {
            buffer.events.remove(0);   // 정렬돼 있으니 index 0 이 가장 오래된 것이다
        }
    }

    /**
     * grace 만큼 이벤트가 끊긴 host 의 대기 트리거를 전부 판정한다.
     * 단말은 배치로 보내므로 배치의 마지막 트리거는 다음 배치(현재 5초)까지 짝을 기다리게 된다.
     * 여기서 wall clock 으로 끊어주지 않으면 탐지가 전송 주기만큼 늦고, 단말이 꺼지면 아예 안 나온다.
     */
    private void flushQuietHosts(long nowWallMs) {
        List<String> quiet = new ArrayList<>();
        for (Map.Entry<String, Long> e : pendingHosts.entrySet()) {
            if (nowWallMs - e.getValue() >= graceMs) {
                quiet.add(e.getKey());   // 순회 중 pendingHosts 를 건드리지 않으려고 먼저 모은다
            }
        }
        // 조용해진 host 만 역직렬화한다. 아직 이벤트가 흐르는 host 는 store 를 읽지도 않는다.
        for (String host : quiet) {
            EventBuffer buffer = store.get(host);
            if (buffer == null) {
                pendingHosts.remove(host);
                continue;
            }
            // grace 를 이미 실제 시간으로 기다렸으니 그 host 가 본 마지막 시각까지 판정한다
            flushPending(host, buffer, buffer.maxTs);
            prune(buffer, buffer.maxTs - graceMs);
            save(host, buffer);
        }
    }

    /** 알림의 레코드 시각은 트리거 이벤트 시각으로 둔다. 발행이 늦어도 하류의 event-time 은 어긋나지 않는다. */
    private void forward(String host, Alert alert) {
        // 도착 순서를 뒤섞어도 탐지 건수가 같다는 것을 보이려면 발행 건수가 지표로 나와야 한다.
        // 태그는 룰과 심각도까지만 둔다. host 나 tenant 를 붙이면 카디널리티가 단말 수만큼 늘어난다.
        metrics.counter("cep.alerts", "rule", alert.ruleId(), "severity", alert.severity()).increment();
        ctx.forward(new Record<>(host, alert, alert.ts()));
    }

    /**
     * 빈 버퍼는 지운다. 남겨두면 스쳐간 host 마다 상태가 하나씩 쌓인다.
     *
     * <p>이벤트 1건마다 버퍼 전체가 다시 직렬화된다(RocksDB 는 값의 부분 갱신이 없다). 그래도 그냥 둔다.
     * "내용이 안 바뀌었으면 put 을 거른다"는 손쉬운 절약이 안 되기 때문이다. maxTs 는 매 이벤트 갱신되고,
     * 그걸 안 남기면 다음 이벤트의 워터마크가 뒤로 밀려 late/pending 분류가 달라진다.
     * 실제로 걸러 보면 lateTrigger_isCountedAndStillEvaluated 가 깨진다.
     *
     * <p>(host, ts) 개별 키로 쪼개는 정공법은 store 구성(DetectionTopology)과 상태 스키마를 바꿔야 하고
     * 워터마크·pending·상한 판정을 다시 짜야 한다. 판정이 바뀔 위험이 이득보다 크다.
     * 참고로 매 이벤트 비용은 직렬화 한 번이 아니라 store.get 의 역직렬화까지 한 쌍이다.
     * 손대야 할 만큼 비싼지는 지표로 먼저 확인할 것.
     */
    private void save(String host, EventBuffer buffer) {
        // store 에 pending 이 남는 유일한 경로가 여기다. 여기서 같이 갱신해야 pendingHosts 가 store 와 어긋나지 않는다.
        if (buffer.pending.isEmpty()) {
            pendingHosts.remove(host);
        } else {
            pendingHosts.put(host, buffer.lastUpdatedWallMs);
        }
        if (buffer.events.isEmpty() && buffer.pending.isEmpty()) {
            store.delete(host);
        } else {
            store.put(host, buffer);
        }
    }

    /** ts 오름차순을 유지하는 삽입. 순서대로 도착하는 흔한 경우엔 끝에 붙어 바로 끝난다. */
    private static void insertByTs(List<Event> sorted, Event e) {
        int i = sorted.size();
        while (i > 0 && sorted.get(i - 1).getTs() > e.getTs()) {
            i--;
        }
        sorted.add(i, e);
    }
}
