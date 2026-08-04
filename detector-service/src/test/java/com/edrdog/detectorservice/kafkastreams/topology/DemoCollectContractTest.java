package com.edrdog.detectorservice.kafkastreams.topology;

import com.edrdog.detectorservice.dto.Alert;
import com.edrdog.detectorservice.kafkastreams.serde.JsonSerde;
import com.edrdog.schema.Event;
import com.edrdog.schema.EventSerde;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.apache.kafka.common.serialization.Serdes;
import org.apache.kafka.streams.TestInputTopic;
import org.apache.kafka.streams.TestOutputTopic;
import org.apache.kafka.streams.StreamsBuilder;
import org.apache.kafka.streams.TopologyTestDriver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * api-service 의 발표용 수집 API(POST /api/demo/collect/{scenario})가 events 토픽에 넣는 값 그대로를
 * 토폴로지에 흘려 의도한 alert 가 나오는지 검증한다.
 *
 * <p>예전에는 여기에 JSON 을 문자열로 박아 두고 필드명이 어긋나는 것을 잡았다. 지금은 양쪽이
 * 같은 {@code .proto} 에서 생성한 클래스를 쓰므로 <b>필드명 어긋남은 컴파일이 막는다.</b>
 * 남은 어긋남 위험은 api-service 가 자기 DTO 를 스키마로 옮기는 자리 한 곳뿐이고,
 * 그건 api-service 쪽 테스트가 지킨다.
 *
 * <p>그래서 이 테스트가 계속 지키는 것은 시나리오별 판정 결과와, 배경 로그가 어떤 룰도
 * 트리거하지 않는다는 것(정확히 1건만 발행된다는 것)이다.
 */
class DemoCollectContractTest {

    private static final String EVENTS = "events";
    private static final String ALERTS = "alerts";
    private static final String HOST = "DESKTOP-DEMO";
    private static final String TENANT = "99";

    /** 발표용 배경 로그 3건. detector 의 baseline 억제 대상 이름이라 어떤 룰도 트리거하지 않아야 한다. */
    private static final List<Event> BACKGROUND = List.of(
            process(88_000, "OneDrive.exe", "explorer.exe",
                    "\"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe\" /background"),
            process(92_000, "Teams.exe", "explorer.exe",
                    "\"C:\\Users\\Public\\AppData\\Local\\Microsoft\\Teams\\Teams.exe\""),
            process(96_000, "MsEdgeUpdate.exe", "services.exe",
                    "\"C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe\" /svc"));

    private TopologyTestDriver driver;
    private TestInputTopic<String, Event> events;
    private TestOutputTopic<String, Alert> alerts;

    @BeforeEach
    void setUp() {
        StreamsBuilder builder = new StreamsBuilder();
        DetectionTopology.build(builder, EVENTS, ALERTS, DetectionTopology.WINDOW_MS,
                DetectionTopology.GRACE_MS, new SimpleMeterRegistry());

        Properties props = new Properties();
        props.put("application.id", "detector-demo-contract");
        props.put("bootstrap.servers", "dummy:9092");

        driver = new TopologyTestDriver(builder.build(), props);
        // 발행 측과 같은 Serde 다. 역직렬화까지 포함해 통과해야 실제로 판정이 성립한 것이다.
        events = driver.createInputTopic(EVENTS, Serdes.String().serializer(),
                new EventSerde().serializer());
        alerts = driver.createOutputTopic(ALERTS, Serdes.String().deserializer(),
                new JsonSerde<>(Alert.class).deserializer());
    }

    @AfterEach
    void tearDown() {
        driver.close();
    }

    @Test
    @DisplayName("배경 로그만 흘리면 어떤 alert 도 안 뜬다")
    void background_noAlert() {
        BACKGROUND.forEach(this::send);

        assertThat(alerts.isEmpty()).isTrue();
    }

    @Test
    @DisplayName("process-chain: 배경 로그 + 매크로 문서 체인 → HIGH 1건만")
    void processChain() {
        BACKGROUND.forEach(this::send);
        send(process(100_000, "winword.exe", "explorer.exe",
                "\"C:\\Users\\kim\\Documents\\견적서_2026.docm\""));
        send(process(101_000, "powershell.exe", "winword.exe",
                "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA..."));
        settle();

        Alert alert = onlyAlert();
        assertThat(alert.ruleId()).isEqualTo("SUSPICIOUS_PROCESS_CHAIN");
        assertThat(alert.mitre()).isEqualTo("T1059");
        assertThat(alert.severity()).isEqualTo(Alert.SEV_HIGH);
        assertThat(alert.ts()).isEqualTo(101_000);      // 판정 ts = 마지막 이벤트 ts (alert id 계산 근거)
        assertThat(alert.tenantId()).isEqualTo(TENANT);
    }

    @Test
    @DisplayName("download-exec: 배경 로그 + 다운로드 후 실행 → CRITICAL 1건만")
    void downloadExec() {
        BACKGROUND.forEach(this::send);
        send(network(100_000, "chrome.exe", "185.220.101.5", 443));
        send(process(101_000, "update32.exe", "explorer.exe",
                "C:\\Users\\choi\\Downloads\\update32.exe"));
        settle();

        Alert alert = onlyAlert();
        assertThat(alert.ruleId()).isEqualTo("DOWNLOAD_AND_EXECUTE");
        assertThat(alert.severity()).isEqualTo(Alert.SEV_CRITICAL);
        assertThat(alert.ts()).isEqualTo(101_000);
    }

    @Test
    @DisplayName("script-exec: 다운로드 경로 스크립트 → MEDIUM 1건만")
    void scriptExec() {
        BACKGROUND.forEach(this::send);
        send(base(100_000, "script")
                .setProcess("powershell.exe")
                .setParent("explorer.exe")
                .setCmdline("powershell -ExecutionPolicy Bypass -File "
                        + "C:\\Users\\park\\Downloads\\invoice_setup.ps1")
                .build());

        Alert alert = onlyAlert();
        assertThat(alert.ruleId()).isEqualTo("SCRIPT_FROM_TEMP_PATH");
        assertThat(alert.severity()).isEqualTo(Alert.SEV_MEDIUM);
        assertThat(alert.ts()).isEqualTo(100_000);
    }

    @Test
    @DisplayName("file-autorun: 시작프로그램 경로 파일 생성 → MEDIUM 1건만")
    void fileAutorun() {
        BACKGROUND.forEach(this::send);
        send(base(100_000, "file")
                .setProcess("svc-update.lnk")
                .setCmdline("C:\\Users\\lee\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu"
                        + "\\Programs\\Startup\\svc-update.lnk")
                .build());

        Alert alert = onlyAlert();
        assertThat(alert.ruleId()).isEqualTo("FILE_IN_AUTORUN_PATH");
        assertThat(alert.mitre()).isEqualTo("T1547");
        assertThat(alert.ts()).isEqualTo(100_000);
    }

    @Test
    @DisplayName("같은 시나리오를 윈도우 안에서 두 번 돌려도 배경 로그가 오탐을 만들지 않는다")
    void repeatedRun_noFalsePositiveOnBackground() {
        // 1회차 network 이벤트가 버퍼에 남은 상태에서 2회차 배경 로그가 들어온다.
        // 배경 프로세스가 baseline 억제 대상이 아니면 여기서 R2 오탐이 잡힌다.
        BACKGROUND.forEach(this::send);
        send(network(100_000, "chrome.exe", "185.220.101.5", 443));
        send(process(101_000, "update32.exe", "explorer.exe",
                "C:\\Users\\choi\\Downloads\\update32.exe"));
        settle();
        assertThat(alerts.getQueueSize()).isEqualTo(1);
        alerts.readValue();

        BACKGROUND.forEach(this::send);   // 2회차 배경 로그 — 오탐이 나오면 안 된다

        assertThat(alerts.isEmpty()).isTrue();
    }

    private void send(Event event) {
        events.pipeInput(HOST, event);
    }

    /** grace 만큼 실제 시간을 흘려 대기 중인 시퀀스 트리거를 판정하게 한다. */
    private void settle() {
        driver.advanceWallClockTime(Duration.ofMillis(DetectionTopology.GRACE_MS * 2));
    }

    private Alert onlyAlert() {
        assertThat(alerts.getQueueSize()).isEqualTo(1);
        return alerts.readValue();
    }

    private static Event process(long ts, String proc, String parent, String cmdline) {
        return base(ts, "process").setProcess(proc).setParent(parent).setCmdline(cmdline).build();
    }

    private static Event network(long ts, String proc, String destIp, int destPort) {
        return base(ts, "network").setProcess(proc).setDestIp(destIp).setDestPort(destPort).build();
    }

    private static Event.Builder base(long ts, String type) {
        return Event.newBuilder().setHost(HOST).setType(type).setTs(ts).setTenantId(TENANT);
    }
}
