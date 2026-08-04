package com.edrdog.collectorservice.agent;

import com.edrdog.schema.Event;
import com.edrdog.schema.EventTypes;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 감소율의 분모가 되는 JSON 환산값을 확인한다.
 * 여기가 틀리면 글에 실리는 숫자가 통째로 틀리는데, 어디서도 에러가 나지 않는다.
 */
class PayloadSizeMeterTest {

    private final MeterRegistry registry = new SimpleMeterRegistry();

    /** 글 본문에 실린 process 샘플과 같은 이벤트. */
    private static Event sample() {
        return Event.newBuilder()
                .setHost("mac-01")
                .setType(EventTypes.PROCESS)
                .setTs(1_754_300_000_000L)
                .setProcess("/usr/bin/curl")
                .setParent("zsh")
                .setCmdline("curl -s http://example.com/payload.sh")
                .setDetail("{\"pid\":41233,\"ppid\":980}")
                .setSha256("a".repeat(64))
                .setTenantId("11111111-1111-1111-1111-111111111111")
                .build();
    }

    private double total(String format) {
        DistributionSummary s = registry.find("event.payload").tag("format", format).summary();
        return s == null ? -1 : s.totalAmount();
    }

    @Test
    @DisplayName("꺼져 있으면 아무것도 재지 않는다 (기본값)")
    void disabledByDefault() {
        new PayloadSizeMeter(registry, false).record(sample(), sample().toByteArray());

        assertThat(registry.find("event.payload").summaries()).isEmpty();
    }

    @Test
    @DisplayName("전환 전 형태를 그대로 되살린다 (빈 필드도 null 로 실린다)")
    void legacyJsonKeepsNullFields() {
        Event e = sample();

        new PayloadSizeMeter(registry, true).record(e, e.toByteArray());

        // 본문 표의 351 B 와 같은 값이어야 한다. 빈 destIp/domain 을 빼면 여기서 어긋난다.
        assertThat(total("json")).isEqualTo(351);
        assertThat(total("protobuf")).isEqualTo(e.toByteArray().length);
    }

    @Test
    @DisplayName("값이 짧은 이벤트일수록 많이 준다")
    void shorterValuesShrinkMore() {
        Event network = Event.newBuilder()
                .setHost("mac-01").setType(EventTypes.NETWORK).setTs(1_754_300_000_000L)
                .setProcess("/usr/bin/curl").setDestIp("203.0.113.24").setDestPort(443)
                .setDetail("{\"pid\":41233,\"protocol\":\"tcp\"}")
                .setTenantId("11111111-1111-1111-1111-111111111111")
                .build();

        PayloadSizeMeter meter = new PayloadSizeMeter(registry, true);
        meter.record(network, network.toByteArray());

        double jsonBytes = total("json");
        double protoBytes = total("protobuf");
        // sha256 이 없어 값이 짧다. 본문 주장대로면 process(-39%)보다 많이 줄어야 한다.
        assertThat(1 - protoBytes / jsonBytes).isGreaterThan(0.45);
    }

    @Test
    @DisplayName("이벤트 종류를 태그로 남긴다 (종류별 감소율 패널의 근거)")
    void tagsEventType() {
        Event e = sample();

        new PayloadSizeMeter(registry, true).record(e, e.toByteArray());

        assertThat(registry.find("event.payload")
                .tag("format", "protobuf").tag("type", EventTypes.PROCESS).summary())
                .isNotNull();
    }
}
