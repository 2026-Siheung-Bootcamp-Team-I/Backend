package com.edrdog.detector.kafkastreams.topology;

import com.edrdog.detector.dto.Alert;
import com.edrdog.detector.dto.Event;
import com.edrdog.detector.kafkastreams.serde.JsonSerde;
import org.apache.kafka.common.serialization.Serdes;
import org.apache.kafka.streams.StreamsBuilder;
import org.apache.kafka.streams.kstream.Consumed;
import org.apache.kafka.streams.kstream.Produced;
import org.apache.kafka.streams.kstream.Repartitioned;
import org.apache.kafka.streams.state.KeyValueStore;
import org.apache.kafka.streams.state.StoreBuilder;
import org.apache.kafka.streams.state.Stores;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * events → 상관분석 → alerts 토폴로지 정의.
 * 입력 이벤트를 host 로 rekey 한 뒤 host 별 상태 저장소 기반으로 시퀀스 상관분석하여 alert 발행.
 */
@Component
public class DetectionTopology {

    /** 상관 윈도우: 이 시간 안의 선행 이벤트만 시퀀스로 인정. */
    public static final long WINDOW_MS = 5 * 60 * 1000L;

    private final String eventsTopic;
    private final String alertsTopic;

    public DetectionTopology(
            @Value("${edrdog.kafka.events-topic}") String eventsTopic,
            @Value("${edrdog.kafka.alerts-topic}") String alertsTopic) {
        this.eventsTopic = eventsTopic;
        this.alertsTopic = alertsTopic;
    }

    /** Spring Kafka Streams 가 주입하는 StreamsBuilder 에 파이프라인 등록. */
    @Autowired
    public void buildPipeline(StreamsBuilder builder) {
        build(builder, eventsTopic, alertsTopic, WINDOW_MS);
    }

    /** 순수 토폴로지 구성 (TopologyTestDriver 테스트에서 직접 호출). */
    public static void build(StreamsBuilder builder, String eventsTopic, String alertsTopic, long windowMs) {
        StoreBuilder<KeyValueStore<String, EventBuffer>> storeBuilder = Stores.keyValueStoreBuilder(
                Stores.persistentKeyValueStore(CorrelationProcessor.STORE),
                Serdes.String(),
                new JsonSerde<>(EventBuffer.class));
        builder.addStateStore(storeBuilder);

        builder.stream(eventsTopic, Consumed.with(Serdes.String(), new JsonSerde<>(Event.class)))
                .selectKey((key, event) -> event == null ? null : event.host())
                // host 기준 재분배 — 같은 host 이벤트를 한 태스크/스토어로 모아 상태 분할 방지
                .repartition(Repartitioned.with(Serdes.String(), new JsonSerde<>(Event.class))
                        .withName("events-by-host"))
                .process(() -> new CorrelationProcessor(windowMs), CorrelationProcessor.STORE)
                .to(alertsTopic, Produced.with(Serdes.String(), new JsonSerde<>(Alert.class)));
    }
}
