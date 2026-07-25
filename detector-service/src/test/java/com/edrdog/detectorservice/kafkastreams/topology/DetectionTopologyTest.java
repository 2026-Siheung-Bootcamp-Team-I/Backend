package com.edrdog.detectorservice.kafkastreams.topology;

import com.edrdog.detectorservice.dto.Alert;
import com.edrdog.detectorservice.dto.Event;
import com.edrdog.detectorservice.kafkastreams.serde.JsonSerde;
import org.apache.kafka.common.serialization.Serdes;
import org.apache.kafka.streams.StreamsBuilder;
import org.apache.kafka.streams.TestInputTopic;
import org.apache.kafka.streams.TestOutputTopic;
import org.apache.kafka.streams.TopologyTestDriver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

/** events → alerts 토폴로지 end-to-end 판정 검증 (TopologyTestDriver). */
class DetectionTopologyTest {

    private static final String EVENTS = "events";
    private static final String ALERTS = "alerts";

    private TopologyTestDriver driver;
    private TestInputTopic<String, Event> events;
    private TestOutputTopic<String, Alert> alerts;

    @BeforeEach
    void setUp() {
        StreamsBuilder builder = new StreamsBuilder();
        DetectionTopology.build(builder, EVENTS, ALERTS, DetectionTopology.WINDOW_MS);

        Properties props = new Properties();
        props.put("application.id", "detector-test");
        props.put("bootstrap.servers", "dummy:9092");

        driver = new TopologyTestDriver(builder.build(), props);
        events = driver.createInputTopic(EVENTS, Serdes.String().serializer(),
                new JsonSerde<>(Event.class).serializer());
        alerts = driver.createOutputTopic(ALERTS, Serdes.String().deserializer(),
                new JsonSerde<>(Alert.class).deserializer());
    }

    @AfterEach
    void tearDown() {
        driver.close();
    }

    private Event process(String host, String proc, String parent, long ts) {
        return new Event(host, Event.TYPE_PROCESS, ts, proc, parent, proc, null, 0, "tenant-a");
    }

    private Event network(String host, int destPort, long ts) {
        return new Event(host, Event.TYPE_NETWORK, ts, null, null, null, "203.0.113.9", destPort, "tenant-a");
    }

    @Test
    @DisplayName("office → shell 시퀀스 → alerts 에 T1059 1건 발행")
    void processChain_emitsAlert() {
        events.pipeInput("k", process("host-1", "winword.exe", "explorer.exe", 1000));
        events.pipeInput("k", process("host-1", "powershell.exe", "winword.exe", 2000));

        assertThat(alerts.getQueueSize()).isEqualTo(1);
        var record = alerts.readKeyValue();
        assertThat(record.key).isEqualTo("host-1");
        assertThat(record.value.ruleId()).isEqualTo("SUSPICIOUS_PROCESS_CHAIN");
        assertThat(record.value.action()).isEqualTo(Alert.ACTION_KILL);
    }

    @Test
    @DisplayName("network 다운로드 → 실행 시퀀스 → alerts 에 CRITICAL 발행")
    void downloadExecute_emitsAlert() {
        events.pipeInput("k", network("host-2", 443, 1000));
        events.pipeInput("k", process("host-2", "evil.exe", "cmd.exe", 2000));

        assertThat(alerts.getQueueSize()).isEqualTo(1);
        assertThat(alerts.readValue().severity()).isEqualTo(Alert.SEV_CRITICAL);
    }

    @Test
    @DisplayName("host 가 다르면 상관되지 않아 미판정")
    void differentHosts_noAlert() {
        events.pipeInput("k", process("host-A", "winword.exe", "explorer.exe", 1000));
        events.pipeInput("k", process("host-B", "powershell.exe", "winword.exe", 2000));

        assertThat(alerts.isEmpty()).isTrue();
    }

    @Test
    @DisplayName("윈도우 밖 선행 이벤트는 시퀀스에서 제외되어 미판정")
    void outsideWindow_noAlert() {
        events.pipeInput("k", process("host-3", "winword.exe", "explorer.exe", 1000));
        long past = 1000 + DetectionTopology.WINDOW_MS + 1;
        events.pipeInput("k", process("host-3", "powershell.exe", "winword.exe", past));

        assertThat(alerts.isEmpty()).isTrue();
    }
}
