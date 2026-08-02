package com.edrdog.collectorservice.agent;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/** 하트비트 응답에 실어 내려줄 수집 설정. 어떤 센서를 켤지와 어떤 경로를 감시할지를 서버가 정한다. */
public final class SensorConfig {

    /** 에이전트가 켤 센서. 지금은 플랫폼과 무관하게 전부 켠다. */
    public record Sensors(boolean process, boolean network, boolean file, boolean dns) {
    }

    public record Config(
            Sensors sensors,
            @JsonProperty("watch_paths") List<String> watchPaths,
            @JsonProperty("flush_interval_seconds") int flushIntervalSeconds
    ) {
    }

    private static final Sensors ALL_SENSORS = new Sensors(true, true, true, true);

    /** 이벤트 배치 전송 주기. 대응 명령도 이 주기로 받아 가므로 조치 체감 지연이 여기에 걸린다. */
    private static final int FLUSH_INTERVAL_SECONDS = 5;

    /** macOS 자동실행 경로. {@code ~} 확장은 에이전트가 한다. */
    private static final List<String> DARWIN_WATCH_PATHS = List.of(
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons",
            "~/Library/LaunchAgents"
    );

    /** Windows 시작프로그램 경로. 사용자별 경로의 {@code *} 는 에이전트가 계정 목록으로 확장한다. */
    private static final List<String> WINDOWS_WATCH_PATHS = List.of(
            "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
            "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
    );

    private SensorConfig() {
    }

    /** enroll 시 저장한 platform 으로 설정을 고른다. */
    public static Config forPlatform(String platform) {
        List<String> watchPaths = isWindows(platform) ? WINDOWS_WATCH_PATHS : DARWIN_WATCH_PATHS;
        return new Config(ALL_SENSORS, watchPaths, FLUSH_INTERVAL_SECONDS);
    }

    /** platform 은 Go 의 {@code runtime.GOOS} 값이다("darwin" 이 "win" 을 포함하므로 "windows" 로 본다). */
    private static boolean isWindows(String platform) {
        return platform != null && platform.trim().toLowerCase().contains("windows");
    }
}
