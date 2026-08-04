package com.edrdog.detectorservice.kafkastreams.topology;

import com.edrdog.detectorservice.dto.Alert;
import com.edrdog.detectorservice.kafkastreams.serde.EventBufferSerde;
import com.edrdog.schema.Event;
import com.edrdog.schema.EventSerde;
import com.edrdog.detectorservice.kafkastreams.serde.JsonSerde;
import io.micrometer.core.instrument.MeterRegistry;
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

    /**
     * 워터마크 허용 지연: 이벤트가 이만큼 늦게 도착하는 것까지 기다린 뒤 시퀀스 룰을 판정한다.
     *
     * <p>워터마크가 host 별이라(EventBuffer.maxTs) 덮어야 할 것은 <b>한 단말 안에서의</b> 어긋남뿐이다.
     * 에이전트는 센서마다 관측 시점에 ts 를 찍고 하나의 FIFO 버퍼에 넣으며, 전송 실패분은 버퍼 앞으로
     * 되돌린다. collector 는 host 를 파티션 키로 발행한다. 그래서 단말 내부 어긋남은 센서 간 채널
     * 경합 수준(밀리초)이고, 1.5초는 그 위의 여유다. 단말 간 전송 주기 차이(5초)는 host 별
     * 워터마크라 애초에 해당되지 않는다.
     *
     * <p>탐지가 이만큼 늦고 그게 곧 kill 이 늦는 것이다. cep.event.lateness p99 와
     * cep.late.events 비율을 보고 확정한다. late 비율이 높으면 이 값이 부족한 것이다.
     */
    public static final long GRACE_MS = 1500L;

    private final String eventsTopic;
    private final String alertsTopic;
    private final long graceMs;
    private final MeterRegistry metrics;

    public DetectionTopology(
            @Value("${edrdog.kafka.events-topic}") String eventsTopic,
            @Value("${edrdog.kafka.alerts-topic}") String alertsTopic,
            @Value("${edrdog.cep.grace-ms:" + GRACE_MS + "}") long graceMs,
            MeterRegistry metrics) {
        this.eventsTopic = eventsTopic;
        this.alertsTopic = alertsTopic;
        this.graceMs = graceMs;
        this.metrics = metrics;
    }

    /** Spring Kafka Streams 가 주입하는 StreamsBuilder 에 파이프라인 등록. */
    @Autowired
    public void buildPipeline(StreamsBuilder builder) {
        build(builder, eventsTopic, alertsTopic, WINDOW_MS, graceMs, metrics);
    }

    /** 순수 토폴로지 구성 (TopologyTestDriver 테스트에서 직접 호출). */
    public static void build(StreamsBuilder builder, String eventsTopic, String alertsTopic,
                             long windowMs, long graceMs, MeterRegistry metrics) {
        StoreBuilder<KeyValueStore<String, EventBuffer>> storeBuilder = Stores.keyValueStoreBuilder(
                Stores.persistentKeyValueStore(CorrelationProcessor.STORE),
                Serdes.String(),
                new EventBufferSerde());
        builder.addStateStore(storeBuilder);

        // 판정 시각 기준은 이벤트의 ts 이고 그건 CorrelationProcessor 가 host 별로 직접 다룬다.
        // 여기서 stream-time 을 손댈 이유가 없다(TimestampExtractor 를 붙여도 읽는 곳이 없다).
        builder.stream(eventsTopic, Consumed.with(Serdes.String(), new EventSerde()))
                .selectKey((key, event) -> event == null ? null : event.getHost())
                // host 기준 재분배 — 같은 host 이벤트를 한 태스크/스토어로 모아 상태 분할 방지
                .repartition(Repartitioned.with(Serdes.String(), new EventSerde())
                        .withName("events-by-host"))
                .process(() -> new CorrelationProcessor(windowMs, graceMs, metrics), CorrelationProcessor.STORE)
                .to(alertsTopic, Produced.with(Serdes.String(), new JsonSerde<>(Alert.class)));
    }
}
