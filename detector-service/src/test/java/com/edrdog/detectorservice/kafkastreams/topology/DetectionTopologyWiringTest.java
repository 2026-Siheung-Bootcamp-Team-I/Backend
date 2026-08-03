package com.edrdog.detectorservice.kafkastreams.topology;

import org.apache.kafka.streams.StreamsBuilder;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.actuate.autoconfigure.metrics.CompositeMeterRegistryAutoConfiguration;
import org.springframework.boot.actuate.autoconfigure.metrics.MetricsAutoConfiguration;
import org.springframework.boot.actuate.autoconfigure.metrics.export.simple.SimpleMetricsExportAutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * DetectionTopology 가 실제 애플리케이션 컨텍스트에서 조립되는지 확인한다.
 * TopologyTestDriver 테스트는 static build() 를 직접 부르므로 MeterRegistry 주입이나
 * grace-ms 프로퍼티가 빠져도 통과한다. 그 구멍은 기동 실패로만 드러나고, 그건 배포 시점이다.
 */
class DetectionTopologyWiringTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    MetricsAutoConfiguration.class,
                    CompositeMeterRegistryAutoConfiguration.class,
                    SimpleMetricsExportAutoConfiguration.class))
            .withBean(StreamsBuilder.class)
            .withUserConfiguration(DetectionTopology.class)
            .withPropertyValues(
                    "edrdog.kafka.events-topic=events",
                    "edrdog.kafka.alerts-topic=alerts");

    @Test
    @DisplayName("MeterRegistry 와 grace-ms 가 주입되어 토폴로지가 조립된다")
    void wiresWithConfiguredGrace() {
        runner.withPropertyValues("edrdog.cep.grace-ms=5000")
                .run(ctx -> assertThat(ctx).hasNotFailed().hasSingleBean(DetectionTopology.class));
    }

    @Test
    @DisplayName("grace-ms 를 안 주면 기본값으로 뜬다")
    void wiresWithDefaultGrace() {
        runner.run(ctx -> assertThat(ctx).hasNotFailed().hasSingleBean(DetectionTopology.class));
    }
}
