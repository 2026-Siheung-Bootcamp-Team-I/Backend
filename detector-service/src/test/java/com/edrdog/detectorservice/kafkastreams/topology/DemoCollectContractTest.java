package com.edrdog.detectorservice.kafkastreams.topology;

import com.edrdog.detectorservice.dto.Alert;
import com.edrdog.detectorservice.dto.Event;
import com.edrdog.detectorservice.kafkastreams.serde.JsonSerde;
import org.apache.kafka.common.serialization.Serdes;
import org.apache.kafka.streams.TestInputTopic;
import org.apache.kafka.streams.TestOutputTopic;
import org.apache.kafka.streams.StreamsBuilder;
import org.apache.kafka.streams.TopologyTestDriver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * api-service 의 발표용 수집 API(POST /api/demo/collect/{scenario})가 events 토픽에 넣는
 * <b>실제 JSON 그대로</b>를 토폴로지에 흘려 의도한 alert 가 나오는지 검증한다.
 *
 * <p>api-service 는 자기 사본 레코드(CollectedEvent)를 직렬화해 발행한다. 필드명이 detector 의
 * {@link Event} 와 하나라도 어긋나면 그 필드가 null 로 역직렬화돼 <b>아무 alert 도 안 뜨고 조용히 실패</b>한다.
 * 발표 당일에 그걸 발견하는 대신 여기서 깨지게 한다. JSON 을 문자열 리터럴로 박는 것이 요점이다 —
 * 양쪽 레코드를 공유하면 이름이 같이 바뀌어 어긋남을 못 잡는다.
 *
 * <p>배경 로그가 어떤 룰도 트리거하지 않는다는 것(정확히 1건만 발행된다는 것)도 같이 확인한다.
 */
class DemoCollectContractTest {

    private static final String EVENTS = "events";
    private static final String ALERTS = "alerts";

    /** 발표용 배경 로그 3건. detector 의 baseline 억제 대상 이름이라 어떤 룰도 트리거하지 않아야 한다. */
    private static final List<String> BACKGROUND = List.of(
            json("DESKTOP-DEMO", "process", 88_000, "OneDrive.exe", "explorer.exe",
                    "\\\"C:\\\\Program Files\\\\Microsoft OneDrive\\\\OneDrive.exe\\\" /background", null, 0),
            json("DESKTOP-DEMO", "process", 92_000, "Teams.exe", "explorer.exe",
                    "\\\"C:\\\\Users\\\\Public\\\\AppData\\\\Local\\\\Microsoft\\\\Teams\\\\Teams.exe\\\"", null, 0),
            json("DESKTOP-DEMO", "process", 96_000, "MsEdgeUpdate.exe", "services.exe",
                    "\\\"C:\\\\Program Files (x86)\\\\Microsoft\\\\EdgeUpdate\\\\MicrosoftEdgeUpdate.exe\\\" /svc", null, 0));

    private TopologyTestDriver driver;
    private TestInputTopic<String, String> events;
    private TestOutputTopic<String, Alert> alerts;

    @BeforeEach
    void setUp() {
        StreamsBuilder builder = new StreamsBuilder();
        DetectionTopology.build(builder, EVENTS, ALERTS, DetectionTopology.WINDOW_MS);

        Properties props = new Properties();
        props.put("application.id", "detector-demo-contract");
        props.put("bootstrap.servers", "dummy:9092");

        driver = new TopologyTestDriver(builder.build(), props);
        // api-service 는 JSON 문자열로 발행한다. 역직렬화까지 포함해 검증하려고 String 으로 넣는다.
        events = driver.createInputTopic(EVENTS, Serdes.String().serializer(), Serdes.String().serializer());
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
        send(json("DESKTOP-DEMO", "process", 100_000, "winword.exe", "explorer.exe",
                "\\\"C:\\\\Users\\\\kim\\\\Documents\\\\견적서_2026.docm\\\"", null, 0));
        send(json("DESKTOP-DEMO", "process", 101_000, "powershell.exe", "winword.exe",
                "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA...", null, 0));

        Alert alert = onlyAlert();
        assertThat(alert.ruleId()).isEqualTo("SUSPICIOUS_PROCESS_CHAIN");
        assertThat(alert.mitre()).isEqualTo("T1059");
        assertThat(alert.severity()).isEqualTo(Alert.SEV_HIGH);
        assertThat(alert.ts()).isEqualTo(101_000);      // 판정 ts = 마지막 이벤트 ts (alert id 계산 근거)
        assertThat(alert.tenantId()).isEqualTo("99");
    }

    @Test
    @DisplayName("download-exec: 배경 로그 + 다운로드 후 실행 → CRITICAL 1건만")
    void downloadExec() {
        BACKGROUND.forEach(this::send);
        send(json("DESKTOP-DEMO", "network", 100_000, "chrome.exe", null, null, "185.220.101.5", 443));
        send(json("DESKTOP-DEMO", "process", 101_000, "update32.exe", "explorer.exe",
                "C:\\\\Users\\\\choi\\\\Downloads\\\\update32.exe", null, 0));

        Alert alert = onlyAlert();
        assertThat(alert.ruleId()).isEqualTo("DOWNLOAD_AND_EXECUTE");
        assertThat(alert.severity()).isEqualTo(Alert.SEV_CRITICAL);
        assertThat(alert.ts()).isEqualTo(101_000);
    }

    @Test
    @DisplayName("script-exec: 다운로드 경로 스크립트 → MEDIUM 1건만")
    void scriptExec() {
        BACKGROUND.forEach(this::send);
        send(json("DESKTOP-DEMO", "script", 100_000, "powershell.exe", "explorer.exe",
                "powershell -ExecutionPolicy Bypass -File C:\\\\Users\\\\park\\\\Downloads\\\\invoice_setup.ps1",
                null, 0));

        Alert alert = onlyAlert();
        assertThat(alert.ruleId()).isEqualTo("SCRIPT_FROM_TEMP_PATH");
        assertThat(alert.severity()).isEqualTo(Alert.SEV_MEDIUM);
        assertThat(alert.ts()).isEqualTo(100_000);
    }

    @Test
    @DisplayName("file-autorun: 시작프로그램 경로 파일 생성 → MEDIUM 1건만")
    void fileAutorun() {
        BACKGROUND.forEach(this::send);
        send(json("DESKTOP-DEMO", "file", 100_000, "svc-update.lnk", null,
                "C:\\\\Users\\\\lee\\\\AppData\\\\Roaming\\\\Microsoft\\\\Windows\\\\Start Menu"
                        + "\\\\Programs\\\\Startup\\\\svc-update.lnk", null, 0));

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
        send(json("DESKTOP-DEMO", "network", 100_000, "chrome.exe", null, null, "185.220.101.5", 443));
        send(json("DESKTOP-DEMO", "process", 101_000, "update32.exe", "explorer.exe",
                "C:\\\\Users\\\\choi\\\\Downloads\\\\update32.exe", null, 0));
        assertThat(alerts.getQueueSize()).isEqualTo(1);
        alerts.readValue();

        BACKGROUND.forEach(this::send);   // 2회차 배경 로그 — 오탐이 나오면 안 된다

        assertThat(alerts.isEmpty()).isTrue();
    }

    private void send(String eventJson) {
        events.pipeInput("DESKTOP-DEMO", eventJson);
    }

    private Alert onlyAlert() {
        assertThat(alerts.getQueueSize()).isEqualTo(1);
        return alerts.readValue();
    }

    /**
     * api-service 의 CollectedEvent 를 Jackson 이 직렬화한 형태 그대로. 필드명을 손으로 적는 것이 요점이다
     * (레코드를 공유하면 이름이 같이 바뀌어 어긋남을 못 잡는다).
     */
    private static String json(String host, String type, long ts, String process, String parent,
                               String cmdline, String destIp, int destPort) {
        return "{\"host\":" + quoted(host)
                + ",\"type\":" + quoted(type)
                + ",\"ts\":" + ts
                + ",\"process\":" + quoted(process)
                + ",\"parent\":" + quoted(parent)
                + ",\"cmdline\":" + quoted(cmdline)
                + ",\"destIp\":" + quoted(destIp)
                + ",\"destPort\":" + destPort
                + ",\"tenantId\":\"99\"}";
    }

    private static String quoted(String value) {
        return value == null ? "null" : "\"" + value + "\"";
    }
}
