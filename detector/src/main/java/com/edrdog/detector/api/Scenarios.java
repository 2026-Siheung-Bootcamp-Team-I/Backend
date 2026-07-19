package com.edrdog.detector.api;

import com.edrdog.detector.dto.Event;

import java.util.List;

/**
 * 데모용 공격 시나리오 팩토리 (순수 함수).
 * 각 시나리오는 detector 룰을 확실히 트리거하도록 같은 host + 윈도우 안(1초 간격) 2개 이벤트를 순서대로 만든다.
 * baseTs 를 인자로 받아 결정적 — 테스트로 재현 가능.
 */
public final class Scenarios {

    private Scenarios() {
    }

    /** 지원 시나리오 이름. */
    public static final String PROCESS_CHAIN = "process-chain";   // R1 T1059 (HIGH)
    public static final String DOWNLOAD_EXEC = "download-exec";   // R2 T1105+T1204 (CRITICAL)

    public static boolean isSupported(String name) {
        return PROCESS_CHAIN.equals(name) || DOWNLOAD_EXEC.equals(name);
    }

    /**
     * 이름에 해당하는 이벤트 시퀀스 생성. 미지원 이름은 IllegalArgumentException.
     *
     * @param name   시나리오 이름 (process-chain | download-exec)
     * @param host   엔드포인트 식별자 (상관분석 키)
     * @param baseTs 첫 이벤트 시각 (epoch millis) — 두 번째는 +1000ms
     */
    public static List<Event> build(String name, String host, long baseTs) {
        return switch (name) {
            case PROCESS_CHAIN -> processChain(host, baseTs);
            case DOWNLOAD_EXEC -> downloadExec(host, baseTs);
            default -> throw new IllegalArgumentException(
                    "미지원 시나리오: " + name + " (지원: " + PROCESS_CHAIN + ", " + DOWNLOAD_EXEC + ")");
        };
    }

    /** office 앱 실행 → 그 앱을 부모로 shell 실행 (매크로 침투 패턴). */
    private static List<Event> processChain(String host, long baseTs) {
        return List.of(
                process(host, baseTs, "winword.exe", "explorer.exe", "\"C:\\docs\\invoice.docm\""),
                process(host, baseTs + 1000, "powershell.exe", "winword.exe",
                        "powershell -enc SQBFAFgA..."));
    }

    /** 다운로드 포트 아웃바운드 → 이후 프로세스 실행 (download-and-execute 패턴). */
    private static List<Event> downloadExec(String host, long baseTs) {
        return List.of(
                network(host, baseTs, "185.220.101.5", 443),
                process(host, baseTs + 1000, "update32.exe", "explorer.exe",
                        "C:\\Users\\Public\\update32.exe"));
    }

    private static Event process(String host, long ts, String proc, String parent, String cmdline) {
        return new Event(host, Event.TYPE_PROCESS, ts, proc, parent, cmdline, null, 0);
    }

    private static Event network(String host, long ts, String destIp, int destPort) {
        return new Event(host, Event.TYPE_NETWORK, ts, null, null, null, destIp, destPort);
    }
}
