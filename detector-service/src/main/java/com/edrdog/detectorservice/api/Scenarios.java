package com.edrdog.detectorservice.api;

import com.edrdog.detectorservice.dto.Event;

import java.util.List;

/**
 * 데모용 공격 시나리오 팩토리 (순수 함수).
 * 시퀀스 룰 시나리오는 같은 host + 윈도우 안(1초 간격) 2개 이벤트를, point 룰 시나리오는 단일 이벤트를 만든다.
 * baseTs 를 인자로 받아 결정적 — 테스트로 재현 가능.
 */
public final class Scenarios {

    private Scenarios() {
    }

    /** 지원 시나리오 이름. */
    public static final String PROCESS_CHAIN = "process-chain";   // R1 T1059 (HIGH)
    public static final String DOWNLOAD_EXEC = "download-exec";   // R2 T1105+T1204 (CRITICAL)
    public static final String SCRIPT_EXEC = "script-exec";       // R3 T1059 (MEDIUM)
    public static final String FILE_AUTORUN = "file-autorun";     // R4 T1547 (MEDIUM)

    public static boolean isSupported(String name) {
        return PROCESS_CHAIN.equals(name) || DOWNLOAD_EXEC.equals(name)
                || SCRIPT_EXEC.equals(name) || FILE_AUTORUN.equals(name);
    }

    /**
     * 이름에 해당하는 이벤트 시퀀스 생성. 미지원 이름은 IllegalArgumentException.
     *
     * @param name     시나리오 이름 (process-chain | download-exec | script-exec | file-autorun)
     * @param host     엔드포인트 식별자 (상관분석 키)
     * @param baseTs   첫 이벤트 시각 (epoch millis) — 시퀀스 시나리오의 두 번째는 +1000ms
     * @param tenantId 조직(tenant) 식별자 — 생성되는 모든 이벤트에 태깅
     */
    public static List<Event> build(String name, String host, long baseTs, String tenantId) {
        return switch (name) {
            case PROCESS_CHAIN -> processChain(host, baseTs, tenantId);
            case DOWNLOAD_EXEC -> downloadExec(host, baseTs, tenantId);
            case SCRIPT_EXEC -> scriptExec(host, baseTs, tenantId);
            case FILE_AUTORUN -> fileAutorun(host, baseTs, tenantId);
            default -> throw new IllegalArgumentException(
                    "미지원 시나리오: " + name + " (지원: " + PROCESS_CHAIN + ", " + DOWNLOAD_EXEC
                            + ", " + SCRIPT_EXEC + ", " + FILE_AUTORUN + ")");
        };
    }

    /** office 앱 실행 → 그 앱을 부모로 shell 실행 (매크로 침투 패턴). */
    private static List<Event> processChain(String host, long baseTs, String tenantId) {
        return List.of(
                process(host, baseTs, "winword.exe", "explorer.exe", "\"C:\\docs\\invoice.docm\"", tenantId),
                process(host, baseTs + 1000, "powershell.exe", "winword.exe",
                        "powershell -enc SQBFAFgA...", tenantId));
    }

    /** 다운로드 포트 아웃바운드 → 이후 프로세스 실행 (download-and-execute 패턴). */
    private static List<Event> downloadExec(String host, long baseTs, String tenantId) {
        return List.of(
                network(host, baseTs, "185.220.101.5", 443, tenantId),
                process(host, baseTs + 1000, "update32.exe", "explorer.exe",
                        "C:\\Users\\Public\\update32.exe", tenantId));
    }

    /** 다운로드 경로의 스크립트 실행 (unsigned/의심 스크립트 → MEDIUM). 단일 이벤트 point 룰. */
    private static List<Event> scriptExec(String host, long baseTs, String tenantId) {
        return List.of(
                script(host, baseTs, "powershell.exe",
                        "powershell -File C:\\Users\\victim\\Downloads\\setup.ps1", tenantId));
    }

    /** 시작프로그램(자동실행) 경로에 파일 생성 (지속성 확보 → MEDIUM). 단일 이벤트 point 룰. */
    private static List<Event> fileAutorun(String host, long baseTs, String tenantId) {
        return List.of(
                file(host, baseTs, "evil.lnk",
                        "C:\\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.lnk",
                        tenantId));
    }

    private static Event process(String host, long ts, String proc, String parent, String cmdline, String tenantId) {
        return new Event(host, Event.TYPE_PROCESS, ts, proc, parent, cmdline, null, 0, tenantId);
    }

    private static Event network(String host, long ts, String destIp, int destPort, String tenantId) {
        return new Event(host, Event.TYPE_NETWORK, ts, null, null, null, destIp, destPort, tenantId);
    }

    /** script 이벤트: cmdline 에 판정용 전체 경로를 담는다(process 는 인터프리터 basename). */
    private static Event script(String host, long ts, String proc, String fullCmdline, String tenantId) {
        return new Event(host, Event.TYPE_SCRIPT, ts, proc, "explorer.exe", fullCmdline, null, 0, tenantId);
    }

    /** file 이벤트: cmdline 에 판정용 전체 경로를 담는다(process 는 파일명 basename). */
    private static Event file(String host, long ts, String name, String fullPath, String tenantId) {
        return new Event(host, Event.TYPE_FILE, ts, name, null, fullPath, null, 0, tenantId);
    }
}
