package com.edrdog.apiservice.demo;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 발표용 공격 시나리오 생성 (순수 함수). baseTs 를 인자로 받아 결정적 — 테스트로 재현 가능.
 *
 * <p>실제 엔드포인트가 로그를 보내는 것처럼 보이게 하려고 공격 이벤트 앞에 <b>정상 배경 로그</b>를 붙인다.
 * 대시보드에서 "이 호스트는 평소 이런 걸 돌리고 있었고, 그 중 이것만 탐지됐다" 로 보인다.
 *
 * <p>배경 로그에 network 이벤트를 넣지 않는 것이 이 클래스의 핵심 제약이다. detector 의 R2 는
 * "선행 network(80/443/8080) + 이후 아무 process" 만으로 CRITICAL 을 내므로, 배경에 network 를 섞으면
 * 뒤따르는 정상 프로세스가 전부 오탐으로 잡힌다. network 는 download-exec 시나리오에서만 의도적으로 쓴다.
 *
 * <p>판정을 트리거하는 이벤트는 항상 <b>마지막</b> 이벤트다. detector 가 만들 alert 의 ts 가 그 이벤트의 ts 와
 * 같아지므로, 호출자는 alert id 를 미리 계산해 도착을 기다릴 수 있다.
 */
public final class DemoScenario {

    private DemoScenario() {
    }

    /** R1 T1059 (HIGH): office 앱이 shell 을 자식으로 띄우는 매크로 침투. */
    public static final String PROCESS_CHAIN = "process-chain";
    /** R2 T1105+T1204 (CRITICAL): 다운로드 아웃바운드 후 그 파일 실행. */
    public static final String DOWNLOAD_EXEC = "download-exec";
    /** R3 T1059 (MEDIUM): 다운로드 경로의 스크립트 실행. */
    public static final String SCRIPT_EXEC = "script-exec";
    /** R4 T1547 (MEDIUM): 시작프로그램 경로에 파일 생성(지속성 확보). */
    public static final String FILE_AUTORUN = "file-autorun";

    private static final List<String> NAMES =
            List.of(PROCESS_CHAIN, DOWNLOAD_EXEC, SCRIPT_EXEC, FILE_AUTORUN);

    /**
     * 시나리오별 기본 host. 서로 다르게 두는 이유가 있다. detector 의 상관 버퍼는 host 별 5분이라
     * 같은 host 로 다른 시나리오를 연달아 돌리면 앞 시나리오의 선행 이벤트가 남아 의도한 룰이 아닌
     * 다른 룰(주로 더 심각한 R2)이 먼저 매칭된다. 발표 중 클릭 순서를 신경 쓰지 않아도 되게 분리한다.
     *
     * <p>이름은 데모 시드가 쓰는 호스트({@link DemoData})와 같은 계열로 맞춰 과거 데이터와 이어져 보이게 한다.
     */
    private static final Map<String, String> DEFAULT_HOSTS = Map.of(
            PROCESS_CHAIN, "DESKTOP-KIM",
            DOWNLOAD_EXEC, "DESKTOP-CHOI",
            SCRIPT_EXEC, "LAPTOP-PARK",
            FILE_AUTORUN, "DESKTOP-LEE");

    /** 시나리오가 트리거할 detector 룰 id. alert 도착을 기다릴 때 쓴다. */
    private static final Map<String, String> RULE_IDS = Map.of(
            PROCESS_CHAIN, "SUSPICIOUS_PROCESS_CHAIN",
            DOWNLOAD_EXEC, "DOWNLOAD_AND_EXECUTE",
            SCRIPT_EXEC, "SCRIPT_FROM_TEMP_PATH",
            FILE_AUTORUN, "FILE_IN_AUTORUN_PATH");

    private static final long SECOND = 1000L;

    public static List<String> names() {
        return NAMES;
    }

    public static boolean isSupported(String name) {
        return name != null && NAMES.contains(name);
    }

    /** 시나리오 기본 host. 미지원 이름은 IllegalArgumentException. */
    public static String defaultHost(String name) {
        return require(DEFAULT_HOSTS, name);
    }

    /** 시나리오가 트리거할 룰 id. 미지원 이름은 IllegalArgumentException. */
    public static String expectedRuleId(String name) {
        return require(RULE_IDS, name);
    }

    /**
     * 정상 배경 로그 + 공격 시퀀스를 시간 순서로 생성한다. 호출자는 이 순서 그대로 발행해야 한다
     * (detector 는 host 파티션 안 도착 순서대로 상관하므로 선행 이벤트가 먼저 나가야 룰이 성립한다).
     *
     * @param name     시나리오 이름
     * @param host     엔드포인트 식별자
     * @param baseTs   공격 첫 이벤트 시각 (epoch millis). 배경 로그는 이보다 앞에 놓인다.
     * @param tenantId 조직(tenant) 식별자 — 발행되는 모든 이벤트에 태깅
     */
    public static List<CollectedEvent> build(String name, String host, long baseTs, String tenantId) {
        if (!isSupported(name)) {
            throw new IllegalArgumentException(
                    "미지원 시나리오: " + name + " (지원: " + String.join(", ", NAMES) + ")");
        }
        List<CollectedEvent> events = new ArrayList<>(background(host, baseTs, tenantId));
        events.addAll(switch (name) {
            case PROCESS_CHAIN -> processChain(host, baseTs, tenantId);
            case DOWNLOAD_EXEC -> downloadExec(host, baseTs, tenantId);
            case SCRIPT_EXEC -> scriptExec(host, baseTs, tenantId);
            default -> fileAutorun(host, baseTs, tenantId);
        });
        return List.copyOf(events);
    }

    /**
     * 평소 돌고 있는 정상 프로세스. detector 의 baseline 억제 목록(Rules.BASELINE_SAFE)에 있는 이름만 쓴다.
     *
     * <p>이름을 아무거나 쓰면 안 되는 이유가 있다. detector 의 상관 버퍼는 host 별 5분이라 같은 시나리오를
     * 5분 안에 두 번 돌리면 앞 회차의 network 이벤트가 버퍼에 남아 있고, R2("선행 network + 이후 아무
     * process")가 이번 회차의 <b>배경</b> 프로세스에 CRITICAL 오탐을 낸다. baseline 억제 대상 이름만 쓰면
     * 그 경로가 원천적으로 막힌다.
     *
     * <p>다른 룰에는 애초에 걸리지 않는다 (R1 은 office 부모 + shell 자식, R3/R4 는 script/file 타입만 본다).
     */
    private static List<CollectedEvent> background(String host, long baseTs, String tenantId) {
        return List.of(
                CollectedEvent.process(host, baseTs - 12 * SECOND, "OneDrive.exe", "explorer.exe",
                        "\"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe\" /background", tenantId),
                CollectedEvent.process(host, baseTs - 8 * SECOND, "Teams.exe", "explorer.exe",
                        "\"C:\\Users\\Public\\AppData\\Local\\Microsoft\\Teams\\Teams.exe\"", tenantId),
                CollectedEvent.process(host, baseTs - 4 * SECOND, "MsEdgeUpdate.exe", "services.exe",
                        "\"C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe\" /svc", tenantId));
    }

    /** office 앱 실행 → 그 앱을 부모로 shell 실행 (매크로 문서 침투). */
    private static List<CollectedEvent> processChain(String host, long baseTs, String tenantId) {
        return List.of(
                CollectedEvent.process(host, baseTs, "winword.exe", "explorer.exe",
                        "\"C:\\Users\\kim\\Documents\\견적서_2026.docm\"", tenantId),
                CollectedEvent.process(host, baseTs + SECOND, "powershell.exe", "winword.exe",
                        "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA...", tenantId));
    }

    /** 외부 다운로드 아웃바운드 → 내려받은 파일 실행 (download-and-execute). */
    private static List<CollectedEvent> downloadExec(String host, long baseTs, String tenantId) {
        return List.of(
                CollectedEvent.network(host, baseTs, "chrome.exe", "185.220.101.5", 443, tenantId),
                CollectedEvent.process(host, baseTs + SECOND, "update32.exe", "explorer.exe",
                        "C:\\Users\\choi\\Downloads\\update32.exe", tenantId));
    }

    /** 다운로드 경로의 스크립트 실행. 단일 이벤트 point 룰. */
    private static List<CollectedEvent> scriptExec(String host, long baseTs, String tenantId) {
        return List.of(CollectedEvent.script(host, baseTs, "powershell.exe", "explorer.exe",
                "powershell -ExecutionPolicy Bypass -File C:\\Users\\park\\Downloads\\invoice_setup.ps1",
                tenantId));
    }

    /** 시작프로그램 경로에 파일 생성. 단일 이벤트 point 룰. */
    private static List<CollectedEvent> fileAutorun(String host, long baseTs, String tenantId) {
        return List.of(CollectedEvent.file(host, baseTs, "svc-update.lnk",
                "C:\\Users\\lee\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\svc-update.lnk",
                tenantId));
    }

    private static String require(Map<String, String> table, String name) {
        String value = name == null ? null : table.get(name);
        if (value == null) {
            throw new IllegalArgumentException(
                    "미지원 시나리오: " + name + " (지원: " + String.join(", ", NAMES) + ")");
        }
        return value;
    }
}
