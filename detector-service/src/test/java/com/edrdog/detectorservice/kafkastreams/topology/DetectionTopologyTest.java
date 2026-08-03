package com.edrdog.detectorservice.kafkastreams.topology;

import com.edrdog.detectorservice.dto.Alert;
import com.edrdog.detectorservice.dto.Event;
import com.edrdog.detectorservice.kafkastreams.serde.JsonSerde;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.apache.kafka.common.serialization.Serdes;
import org.apache.kafka.streams.StreamsBuilder;
import org.apache.kafka.streams.TestInputTopic;
import org.apache.kafka.streams.TestOutputTopic;
import org.apache.kafka.streams.TopologyTestDriver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

/** events → alerts 토폴로지 end-to-end 판정 검증 (TopologyTestDriver). */
class DetectionTopologyTest {

    private static final String EVENTS = "events";
    private static final String ALERTS = "alerts";
    private static final long GRACE_MS = DetectionTopology.GRACE_MS;

    private TopologyTestDriver driver;
    private TestInputTopic<String, Event> events;
    private TestOutputTopic<String, Alert> alerts;
    private MeterRegistry metrics;

    @BeforeEach
    void setUp() {
        StreamsBuilder builder = new StreamsBuilder();
        metrics = new SimpleMeterRegistry();
        DetectionTopology.build(builder, EVENTS, ALERTS, DetectionTopology.WINDOW_MS, GRACE_MS, metrics);

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
        return new Event(host, Event.TYPE_PROCESS, ts, proc, parent, proc, null, 0, null, null, null, "tenant-a");
    }

    /** cmdline 을 직접 주는 process 이벤트. R2 는 실행 경로를 본다. */
    private Event processFrom(String host, String proc, String cmdline, long ts) {
        return new Event(host, Event.TYPE_PROCESS, ts, proc, "explorer.exe", cmdline, null, 0, null, null, null, "tenant-a");
    }

    private Event network(String host, int destPort, long ts) {
        return new Event(host, Event.TYPE_NETWORK, ts, null, null, null, "203.0.113.9", destPort, null, null, null, "tenant-a");
    }

    /** 목적지 도메인까지 관측된 network 이벤트. */
    private Event networkTo(String host, String destIp, String domain, int destPort, long ts) {
        return new Event(host, Event.TYPE_NETWORK, ts, null, null, null, destIp, destPort, domain, null, null, "tenant-a");
    }

    /**
     * grace 만큼 실제 시간을 흘려 조용해진 host 의 대기 트리거를 판정하게 한다.
     * 시퀀스 룰은 워터마크 이후에 판정하므로 이 호출 없이는 알림이 나오지 않는다.
     */
    private void settle() {
        driver.advanceWallClockTime(Duration.ofMillis(GRACE_MS * 2));
    }

    private double lateCount() {
        return metrics.find("cep.late.events").counters().stream()
                .mapToDouble(c -> c.count()).sum();
    }

    @Test
    @DisplayName("office → shell 시퀀스 → alerts 에 T1059 1건 발행")
    void processChain_emitsAlert() {
        events.pipeInput("k", process("host-1", "winword.exe", "explorer.exe", 1000));
        events.pipeInput("k", process("host-1", "powershell.exe", "winword.exe", 2000));
        settle();

        assertThat(alerts.getQueueSize()).isEqualTo(1);
        var record = alerts.readKeyValue();
        assertThat(record.key).isEqualTo("host-1");
        assertThat(record.value.ruleId()).isEqualTo("SUSPICIOUS_PROCESS_CHAIN");
        assertThat(record.value.action()).isEqualTo(Alert.ACTION_KILL);
    }

    @Test
    @DisplayName("R1 역순 도착: shell 이 office 실행보다 먼저 도착해도 시각 순서로 판정한다")
    void processChain_reversedArrival_emitsAlert() {
        // 도착 순서만 보던 시절에는 이 조합이 영영 미탐이었다. shell 은 버퍼에 남지 않아
        // 뒤늦게 온 office 실행이 짝을 찾을 방법이 없었다.
        events.pipeInput("k", process("host-1", "powershell.exe", "winword.exe", 2000));
        events.pipeInput("k", process("host-1", "winword.exe", "explorer.exe", 1000));
        settle();

        assertThat(alerts.getQueueSize()).isEqualTo(1);
        assertThat(alerts.readValue().ruleId()).isEqualTo("SUSPICIOUS_PROCESS_CHAIN");
    }

    @Test
    @DisplayName("network 다운로드 → 실행 시퀀스 → alerts 에 CRITICAL 발행")
    void downloadExecute_emitsAlert() {
        events.pipeInput("k", network("host-2", 443, 1000));
        events.pipeInput("k", processFrom("host-2", "evil.exe", "C:\\Users\\me\\Downloads\\evil.exe", 2000));
        settle();

        assertThat(alerts.getQueueSize()).isEqualTo(1);
        assertThat(alerts.readValue().severity()).isEqualTo(Alert.SEV_CRITICAL);
    }

    @Test
    @DisplayName("R2 역순 도착: network 이벤트가 실행보다 늦게 도착해도 판정한다")
    void downloadExecute_networkArrivesLate_emitsAlert() {
        // 네트워크 이벤트는 연결이 끝난 뒤에 기록돼 늘 늦게 도착한다(실측: 실기기에서 R2 미발화).
        events.pipeInput("k", processFrom("host-2", "evil.exe", "C:\\Users\\me\\Downloads\\evil.exe", 2000));
        events.pipeInput("k", network("host-2", 443, 1000));
        settle();

        assertThat(alerts.getQueueSize()).isEqualTo(1);
        assertThat(alerts.readValue().ruleId()).isEqualTo("DOWNLOAD_AND_EXECUTE");
    }

    @Test
    @DisplayName("점 룰(단일 이벤트)은 워터마크를 기다리지 않고 즉시 발행한다")
    void pointRule_emitsImmediately() {
        // 기다려서 얻는 게 없는데 지연을 물면 대응만 늦어진다.
        Event script = new Event("host-6", Event.TYPE_SCRIPT, 1000, "zsh", "explorer.exe",
                "/bin/zsh /tmp/evil.sh", null, 0, null, null, null, "tenant-a");
        events.pipeInput("k", script);

        assertThat(alerts.getQueueSize()).isEqualTo(1);
        assertThat(alerts.readValue().ruleId()).isEqualTo("SCRIPT_FROM_TEMP_PATH");
    }

    @Test
    @DisplayName("한 트리거는 한 번만 판정한다 (워터마크가 계속 밀려도 중복 발행 없음)")
    void sequenceAlert_emittedOnce() {
        // 중복 발행되면 responder 가 같은 프로세스에 kill 을 여러 번 쏜다.
        events.pipeInput("k", process("host-1", "winword.exe", "explorer.exe", 1000));
        events.pipeInput("k", process("host-1", "powershell.exe", "winword.exe", 2000));
        settle();
        settle();
        driver.advanceWallClockTime(Duration.ofSeconds(10));

        assertThat(alerts.getQueueSize()).isEqualTo(1);
    }

    @Test
    @DisplayName("같은 단말의 다음 이벤트가 워터마크를 넘기면 실제 시간을 기다리지 않고 판정한다")
    void ownNextEvent_flushesPending() {
        // 이벤트가 계속 흐르는 단말의 빠른 경로다. 이게 없으면 모든 판정이 wall clock 백스톱을 기다린다.
        events.pipeInput("k", process("host-1", "winword.exe", "explorer.exe", 1000));
        events.pipeInput("k", process("host-1", "powershell.exe", "winword.exe", 2000));
        assertThat(alerts.isEmpty()).isTrue();

        events.pipeInput("k", process("host-1", "idle", "launchd", 2000 + GRACE_MS + 1));

        assertThat(alerts.getQueueSize()).isEqualTo(1);
        assertThat(alerts.readValue().ruleId()).isEqualTo("SUSPICIOUS_PROCESS_CHAIN");
    }

    @Test
    @DisplayName("단말이 조용해져도 대기 중이던 트리거는 판정된다")
    void quietHost_pendingIsFlushed() {
        // stream-time 만 보면 마지막 이벤트가 영영 판정되지 않는다. 공격의 마지막 행동이 거기 있다.
        events.pipeInput("k", process("host-1", "winword.exe", "explorer.exe", 1000));
        events.pipeInput("k", process("host-1", "powershell.exe", "winword.exe", 2000));
        assertThat(alerts.isEmpty()).isTrue();

        driver.advanceWallClockTime(Duration.ofMillis(GRACE_MS * 2));

        assertThat(alerts.getQueueSize()).isEqualTo(1);
        assertThat(alerts.readValue().ruleId()).isEqualTo("SUSPICIOUS_PROCESS_CHAIN");
    }

    @Test
    @DisplayName("워터마크를 넘겨 도착한 트리거는 카운터를 남기고 그 자리에서 판정한다")
    void lateTrigger_isCountedAndStillEvaluated() {
        // 버리면 확정 미탐이다. 짝이 이미 버퍼에 있으면 최선을 다해 잡고, 카운터로 grace 가 부족함을 알린다.
        events.pipeInput("k", network("host-7", 443, 1000));
        // 같은 host 의 최신 이벤트가 워터마크를 2000 너머로 민다 (워터마크는 host 별이다)
        events.pipeInput("k", process("host-7", "idle", "launchd", 2000 + GRACE_MS * 2));
        events.pipeInput("k", processFrom("host-7", "evil.exe", "/Users/me/Downloads/evil.exe", 2000));

        assertThat(lateCount()).isEqualTo(1);
        assertThat(alerts.getQueueSize()).isEqualTo(1);
        assertThat(alerts.readValue().ruleId()).isEqualTo("DOWNLOAD_AND_EXECUTE");
    }

    @Test
    @DisplayName("근거 이벤트의 목적지가 alert 에 실리고, 도착 순서가 달라도 같은 값이다")
    void destination_isIndependentOfArrivalOrder() {
        // 룰은 도착 순서에 독립적으로 판정한다. 목적지도 같아야 한다(안 그러면 같은 공격이 절반만 그려진다).
        events.pipeInput("k", processFrom("host-4", "evil.exe", "C:\\Users\\me\\Downloads\\evil.exe", 2000));
        events.pipeInput("k", networkTo("host-4", "203.0.113.9", "evil.example.com", 443, 1000));
        settle();
        Alert late = alerts.readValue();

        events.pipeInput("k", networkTo("host-5", "203.0.113.9", "evil.example.com", 443, 10_000));
        events.pipeInput("k", processFrom("host-5", "evil.exe", "C:\\Users\\me\\Downloads\\evil.exe", 11_000));
        settle();
        Alert inOrder = alerts.readValue();

        assertThat(late.ruleId()).isEqualTo("DOWNLOAD_AND_EXECUTE");
        assertThat(late.destIp()).isEqualTo("203.0.113.9");
        assertThat(late.domain()).isEqualTo("evil.example.com");
        assertThat(inOrder.destIp()).isEqualTo(late.destIp());
        assertThat(inOrder.domain()).isEqualTo(late.domain());
    }

    @Test
    @DisplayName("판정 근거가 어떤 목적지도 관측하지 못했으면 빈 문자열 (지어내지 않는다)")
    void noDestinationObserved_isEmpty() {
        events.pipeInput("k", process("host-5", "winword.exe", "explorer.exe", 1000));
        events.pipeInput("k", process("host-5", "powershell.exe", "winword.exe", 2000));
        settle();

        Alert alert = alerts.readValue();
        assertThat(alert.destIp()).isEmpty();
        assertThat(alert.domain()).isEmpty();
    }

    @Test
    @DisplayName("host 가 다르면 상관되지 않아 미판정")
    void differentHosts_noAlert() {
        events.pipeInput("k", process("host-A", "winword.exe", "explorer.exe", 1000));
        events.pipeInput("k", process("host-B", "powershell.exe", "winword.exe", 2000));
        settle();

        assertThat(alerts.isEmpty()).isTrue();
    }

    @Test
    @DisplayName("윈도우 밖 선행 이벤트는 시퀀스에서 제외되어 미판정")
    void outsideWindow_noAlert() {
        events.pipeInput("k", process("host-3", "winword.exe", "explorer.exe", 1000));
        long past = 1000 + DetectionTopology.WINDOW_MS + 1;
        events.pipeInput("k", process("host-3", "powershell.exe", "winword.exe", past));
        settle();

        assertThat(alerts.isEmpty()).isTrue();
    }

    @Test
    @DisplayName("무관한 이벤트가 버퍼 상한을 넘게 쏟아져도 상관은 유지된다")
    void noisyBuffer_keepsCorrelation() {
        // 실기기(맥북)는 초당 15건씩 프로세스 이벤트를 낸다. 버퍼가 최근 N건만 보관하면
        // 5분 윈도우가 사실상 십여 초로 줄어 R2 가 거의 발화하지 못한다(실측).
        events.pipeInput("k", network("host-3", 443, 1000));
        for (int i = 0; i < 500; i++) {
            events.pipeInput("k", process("host-3", "noise" + i, "bash", 1000 + i));
        }
        events.pipeInput("k", processFrom("host-3", "evil", "/Users/me/Downloads/evil", 200_000));
        settle();

        assertThat(alerts.getQueueSize()).isEqualTo(1);
        assertThat(alerts.readValue().ruleId()).isEqualTo("DOWNLOAD_AND_EXECUTE");
    }
}
