package com.edrdog.detectorservice.kafkastreams.health;

import org.apache.kafka.streams.KafkaStreams;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.Status;
import org.springframework.kafka.config.StreamsBuilderFactoryBean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Streams 상태를 readiness 관점으로 옮기는 규칙. 리밸런싱은 정상, 나머지 비정상 상태는 트래픽을 받으면 안 된다. */
class KafkaStreamsHealthIndicatorTest {

    private final StreamsBuilderFactoryBean factoryBean = mock(StreamsBuilderFactoryBean.class);
    private final KafkaStreamsHealthIndicator indicator = new KafkaStreamsHealthIndicator(factoryBean);

    @Test
    @DisplayName("RUNNING 이면 UP")
    void running_up() {
        assertThat(healthOf(KafkaStreams.State.RUNNING).getStatus()).isEqualTo(Status.UP);
    }

    @Test
    @DisplayName("REBALANCING 은 정상 과정이라 UP (DOWN 이면 리밸런싱마다 파드가 빠진다)")
    void rebalancing_up() {
        assertThat(healthOf(KafkaStreams.State.REBALANCING).getStatus()).isEqualTo(Status.UP);
    }

    @ParameterizedTest
    @EnumSource(value = KafkaStreams.State.class,
            names = {"CREATED", "PENDING_SHUTDOWN", "NOT_RUNNING", "PENDING_ERROR", "ERROR"})
    @DisplayName("판정이 안 도는 상태는 모두 DOWN")
    void notProcessing_down(KafkaStreams.State state) {
        Health health = healthOf(state);
        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
        assertThat(health.getDetails()).containsEntry("state", state.name());
    }

    @Test
    @DisplayName("기동 초기라 Streams 인스턴스가 아직 없으면 예외 없이 DOWN")
    void notStarted_down() {
        when(factoryBean.getKafkaStreams()).thenReturn(null);

        Health health = indicator.health();

        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
        assertThat(health.getDetails()).containsEntry("state", "NOT_STARTED");
    }

    private Health healthOf(KafkaStreams.State state) {
        KafkaStreams streams = mock(KafkaStreams.class);
        when(streams.state()).thenReturn(state);
        when(factoryBean.getKafkaStreams()).thenReturn(streams);
        return indicator.health();
    }
}
