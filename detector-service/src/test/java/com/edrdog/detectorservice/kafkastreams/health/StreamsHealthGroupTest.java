package com.edrdog.detectorservice.kafkastreams.health;

import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.streams.KafkaStreams;
import org.apache.kafka.streams.StreamsConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.actuate.autoconfigure.availability.AvailabilityHealthContributorAutoConfiguration;
import org.springframework.boot.actuate.autoconfigure.availability.AvailabilityProbesAutoConfiguration;
import org.springframework.boot.actuate.autoconfigure.health.HealthEndpointAutoConfiguration;
import org.springframework.boot.actuate.health.HealthEndpoint;
import org.springframework.boot.actuate.health.HealthEndpointGroups;
import org.springframework.boot.actuate.health.Status;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.availability.ApplicationAvailabilityAutoConfiguration;
import org.springframework.boot.availability.AvailabilityChangeEvent;
import org.springframework.boot.availability.LivenessState;
import org.springframework.boot.availability.ReadinessState;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.kafka.config.KafkaStreamsConfiguration;
import org.springframework.kafka.config.StreamsBuilderFactoryBean;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * health group 설정이 실제로 먹는지 본다. 지표만 만들고 그룹에 안 들어가면 probe 는 여전히 UP 이라
 * 아무것도 안 하는 코드가 된다.
 * 프로퍼티를 테스트에 다시 적지 않고 ConfigData 로 실제 application.yml 을 읽는 이유가 이것이다.
 * 이름이 없는 항목을 include 하면 컨텍스트 기동 자체가 깨지므로(NoSuchHealthContributorException)
 * 오타는 이 테스트가 뜨는 것만으로도 걸린다.
 */
class StreamsHealthGroupTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withInitializer(new ConfigDataApplicationContextInitializer())
            .withConfiguration(AutoConfigurations.of(
                    ApplicationAvailabilityAutoConfiguration.class,
                    AvailabilityHealthContributorAutoConfiguration.class,
                    AvailabilityProbesAutoConfiguration.class,   // probes 를 켜야 livenessState/readinessState 지표가 생긴다
                    HealthEndpointAutoConfiguration.class))
            .withBean(StubStreamsFactoryBean.class)
            .withUserConfiguration(KafkaStreamsHealthIndicator.class);

    @Test
    @DisplayName("readiness 그룹에 kafkaStreams 가 들어가고 liveness 에는 안 들어간다")
    void groupMembership() {
        runner.run(ctx -> {
            HealthEndpointGroups groups = ctx.getBean(HealthEndpointGroups.class);
            assertThat(groups.get("readiness").isMember("kafkaStreams")).isTrue();
            assertThat(groups.get("liveness").isMember("kafkaStreams")).isFalse();
        });
    }

    @Test
    @DisplayName("Streams 가 ERROR 면 readiness 가 DOWN, liveness 는 UP 그대로")
    void streamsError_readinessDown() {
        runner.run(ctx -> {
            started(ctx);
            streamsState(ctx, KafkaStreams.State.ERROR);

            HealthEndpoint endpoint = ctx.getBean(HealthEndpoint.class);
            assertThat(endpoint.healthForPath("readiness").getStatus()).isEqualTo(Status.DOWN);
            assertThat(endpoint.healthForPath("liveness").getStatus()).isEqualTo(Status.UP);
        });
    }

    @Test
    @DisplayName("Streams 가 RUNNING 이면 readiness 가 UP")
    void streamsRunning_readinessUp() {
        runner.run(ctx -> {
            started(ctx);
            streamsState(ctx, KafkaStreams.State.RUNNING);

            assertThat(ctx.getBean(HealthEndpoint.class).healthForPath("readiness").getStatus())
                    .isEqualTo(Status.UP);
        });
    }

    /**
     * 기동이 끝난 상태를 만든다. 두 상태 모두 초기값(BROKEN / REFUSING_TRAFFIC)이라 그냥 두면
     * 그룹이 늘 DOWN 이고 Streams 판정이 거기 묻힌다.
     */
    private static void started(org.springframework.context.ApplicationContext ctx) {
        AvailabilityChangeEvent.publish(ctx, LivenessState.CORRECT);
        AvailabilityChangeEvent.publish(ctx, ReadinessState.ACCEPTING_TRAFFIC);
    }

    private static void streamsState(org.springframework.context.ApplicationContext ctx, KafkaStreams.State state) {
        KafkaStreams streams = mock(KafkaStreams.class);
        when(streams.state()).thenReturn(state);
        ctx.getBean(StubStreamsFactoryBean.class).setKafkaStreams(streams);
    }

    /**
     * 목이 아니라 실제 FactoryBean 을 상속한다. 목으로 바꾸면 지표가 FactoryBean 을 타입으로 주입받는 게
     * 실제로 되는지(FactoryBean 은 &이름으로 등록된다) 확인이 안 된다.
     */
    static class StubStreamsFactoryBean extends StreamsBuilderFactoryBean {

        private KafkaStreams streams;

        StubStreamsFactoryBean() {
            super(new KafkaStreamsConfiguration(Map.of(
                    StreamsConfig.APPLICATION_ID_CONFIG, "detector-test",
                    ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, "localhost:9092")));
            setAutoStartup(false);   // 테스트에서 Kafka 에 붙지 않는다
        }

        void setKafkaStreams(KafkaStreams streams) {
            this.streams = streams;
        }

        @Override
        public synchronized KafkaStreams getKafkaStreams() {
            return streams;   // 세팅 전에는 null 이라 기동 초기 상황과 같다
        }
    }
}
