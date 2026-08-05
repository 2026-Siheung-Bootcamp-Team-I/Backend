package com.edrdog.detectorservice.kafkastreams.health;

import org.apache.kafka.streams.KafkaStreams;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.kafka.config.StreamsBuilderFactoryBean;
import org.springframework.stereotype.Component;

/**
 * Kafka Streams 상태를 health 에 싣는다.
 * actuator 기본 항목에는 Streams 가 없어서 태스크가 ERROR 로 죽어도 /actuator/health 는 UP 이었고,
 * 탐지가 통째로 멈춘 채 배포가 초록으로 끝났다(이슈 #214).
 * 빈 이름이 kafkaStreamsHealthIndicator 라 health 항목 이름은 kafkaStreams 가 된다.
 * application.yml 의 readiness 그룹 include 가 이 이름을 가리킨다.
 */
@Component
public class KafkaStreamsHealthIndicator implements HealthIndicator {

    private final StreamsBuilderFactoryBean factoryBean;

    public KafkaStreamsHealthIndicator(StreamsBuilderFactoryBean factoryBean) {
        this.factoryBean = factoryBean;
    }

    @Override
    public Health health() {
        KafkaStreams streams = factoryBean.getKafkaStreams();
        // 기동 초기엔 인스턴스가 아직 없다. 아직 준비가 안 된 것이므로 DOWN 이되, NPE 로 health 자체를 깨뜨리지는 않는다.
        if (streams == null) {
            return Health.down().withDetail("state", "NOT_STARTED").build();
        }

        KafkaStreams.State state = streams.state();
        // RUNNING 과 REBALANCING 만 UP 이다. 리밸런싱은 태스크 재배치라 정상 과정이고,
        // 이걸 DOWN 으로 보면 리밸런싱이 일어날 때마다 파드가 엔드포인트에서 빠진다.
        // 나머지(CREATED, PENDING_SHUTDOWN, NOT_RUNNING, PENDING_ERROR, ERROR)는 판정이 안 도는 상태다.
        // CREATED 는 고장은 아니지만 아직 이벤트를 처리하지 않으므로 readiness 기준으로는 DOWN 이다.
        // 판정을 enum 자체 헬퍼에 맡겨야 Streams 가 상태를 늘려도 여기가 어긋나지 않는다.
        return (state.isRunningOrRebalancing() ? Health.up() : Health.down())
                .withDetail("state", state.name())
                .build();
    }
}
