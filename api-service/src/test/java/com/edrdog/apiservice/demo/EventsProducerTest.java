package com.edrdog.apiservice.demo;

import com.edrdog.schema.Event;
import com.edrdog.schema.EventHeaders;
import com.edrdog.schema.EventTypes;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.kafka.core.KafkaTemplate;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * 데모 이벤트가 events 토픽에 나가는 형태의 계약.
 * 파티션 키와 헤더는 본문과 달리 발행하는 쪽에서만 정해지므로 여기서 확인한다.
 */
class EventsProducerTest {

    @SuppressWarnings("unchecked")
    private final KafkaTemplate<String, byte[]> template = mock(KafkaTemplate.class);

    private final EventsProducer producer = new EventsProducer(template, "events");

    private static Event sample() {
        return Event.newBuilder()
                .setHost("PC-01")
                .setType(EventTypes.PROCESS)
                .setTs(1_000L)
                .setProcess("powershell.exe")
                .setParent("winword.exe")
                .setCmdline("powershell -enc AAAA")
                .setTenantId("99")
                .build();
    }

    private ProducerRecord<String, byte[]> publish(Event event) {
        producer.publish(event);
        ArgumentCaptor<ProducerRecord<String, byte[]>> captor = ArgumentCaptor.forClass(ProducerRecord.class);
        verify(template).send(captor.capture());
        return captor.getValue();
    }

    @Test
    @DisplayName("본문은 되읽으면 발행한 이벤트 그대로다")
    void bodyIsTheEventItself() throws Exception {
        ProducerRecord<String, byte[]> record = publish(sample());

        assertThat(Event.parseFrom(record.value())).isEqualTo(sample());
    }

    @Test
    @DisplayName("파티션 키는 host 다 (바뀌면 같은 단말의 순서가 깨진다)")
    void partitionKeyIsHost() {
        assertThat(publish(sample()).key()).isEqualTo("PC-01");
    }

    @Test
    @DisplayName("본문을 풀지 않고도 볼 수 있게 헤더를 싣는다")
    void headersAreStamped() {
        ProducerRecord<String, byte[]> record = publish(sample());

        assertThat(header(record, EventHeaders.SCHEMA_VERSION)).isEqualTo(EventHeaders.CURRENT_SCHEMA_VERSION);
        assertThat(header(record, EventHeaders.EVENT_TYPE)).isEqualTo(EventTypes.PROCESS);
        assertThat(header(record, EventHeaders.TENANT_ID)).isEqualTo("99");
    }

    @Test
    @DisplayName("tenantId 가 본문과 헤더 양쪽에 실린다 (테스트 계정 화면에 뜨는 근거)")
    void tenantIdSurvivesPublishing() throws Exception {
        ProducerRecord<String, byte[]> record = publish(sample());

        assertThat(Event.parseFrom(record.value()).getTenantId()).isEqualTo("99");
        assertThat(header(record, EventHeaders.TENANT_ID)).isEqualTo("99");
    }

    private static String header(ProducerRecord<String, byte[]> record, String key) {
        return new String(record.headers().lastHeader(key).value(), StandardCharsets.UTF_8);
    }
}
