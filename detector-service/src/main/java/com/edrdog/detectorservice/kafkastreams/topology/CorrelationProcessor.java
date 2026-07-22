package com.edrdog.detectorservice.kafkastreams.topology;

import com.edrdog.detectorservice.dto.Alert;
import com.edrdog.detectorservice.dto.Event;
import com.edrdog.detectorservice.rule.Rules;
import org.apache.kafka.streams.processor.api.Processor;
import org.apache.kafka.streams.processor.api.ProcessorContext;
import org.apache.kafka.streams.processor.api.Record;
import org.apache.kafka.streams.state.KeyValueStore;

/**
 * host(key) 별 이벤트 버퍼를 유지하며 시퀀스 상관분석을 수행.
 * 각 이벤트마다: 윈도우 밖 선행 이벤트 제거 → 룰 판정 → 현재 이벤트 버퍼 적재 → 매칭 시 Alert 발행.
 * event-time(이벤트 ts) 기준이라 결정적 — TopologyTestDriver 로 재현 가능.
 */
public class CorrelationProcessor implements Processor<String, Event, String, Alert> {

    static final String STORE = "event-buffer";

    private final long windowMs;
    private KeyValueStore<String, EventBuffer> store;
    private ProcessorContext<String, Alert> ctx;

    public CorrelationProcessor(long windowMs) {
        this.windowMs = windowMs;
    }

    @Override
    public void init(ProcessorContext<String, Alert> context) {
        this.ctx = context;
        this.store = context.getStateStore(STORE);
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
        // 윈도우 밖(현재 이벤트 기준) 선행 이벤트 제거
        buffer.events.removeIf(prev -> current.ts() - prev.ts() > windowMs);

        // 선행 버퍼 + 현재 이벤트 상관 판정
        Rules.evaluate(buffer.events, current).ifPresent(alert ->
                ctx.forward(record.withKey(host).withValue(alert)));

        // 현재 이벤트 적재 (상한 초과 시 가장 오래된 것부터 제거)
        buffer.events.add(current);
        while (buffer.events.size() > EventBuffer.MAX) {
            buffer.events.remove(0);
        }
        store.put(host, buffer);
    }
}
