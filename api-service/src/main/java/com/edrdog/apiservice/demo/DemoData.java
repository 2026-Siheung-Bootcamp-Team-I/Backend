package com.edrdog.apiservice.demo;

import com.edrdog.apiservice.alert.dto.Alert;

import java.util.ArrayList;
import java.util.List;

/**
 * 발표용 과거 데이터 생성 (순수 함수). 기준 시각 nowTs 를 받아 최근 {@link #DAYS} 일치를 결정적으로 만든다.
 *
 * <p>이 데이터는 Kafka 를 거치지 않고 저장소에 바로 적재된다(과거 시각으로는 detector 의 상관 윈도우가
 * 성립하지 않기 때문). 실시간 시연은 detector 의 시나리오 발행 API 로 하고, 여기서는 "이미 운영 중이던
 * 흔적"만 채운다.
 *
 * <p>화면이 골고루 차도록 다음을 보장한다.
 * <ul>
 *   <li>호스트 도넛: 위험/주의/정상이 모두 나오게 alert 없는 호스트({@link #QUIET_HOSTS})를 남긴다</li>
 *   <li>severity 분포·카테고리 집계: 룰 4종과 심각도 3종을 모두 포함한다</li>
 *   <li>lineage: alert 마다 같은 host 의 근거 이벤트를 같은 시각대에 함께 넣는다</li>
 * </ul>
 */
public final class DemoData {

    /** 과거 데이터를 채우는 기간(일). */
    public static final int DAYS = 7;

    /** alert 가 하나도 없는 정상 호스트. 도넛이 위험 색으로만 차는 걸 막는다. */
    public static final List<String> QUIET_HOSTS = List.of("SRV-DB-01", "SRV-WEB-01");

    /**
     * 데모 데이터가 이미 적재됐는지 판별하는 대표 호스트. 이 호스트의 events 유무로 재적재를 결정한다.
     * "events 가 하나라도 있으면 skip" 으로 하면 개발 중 남은 다른 이벤트에 가려 데모 데이터가 안 채워진다.
     */
    public static final String MARKER_HOST = "DESKTOP-KIM";

    /** alert 가 있는 호스트. */
    static final List<String> NOISY_HOSTS = List.of(MARKER_HOST, "DESKTOP-CHOI", "DESKTOP-LEE", "LAPTOP-PARK");

    private static final long HOUR = 60 * 60 * 1000L;
    private static final long MINUTE = 60 * 1000L;

    /** 배경 소음용 정상 프로세스. 이것만 있는 호스트는 alert 가 안 생긴다. */
    private static final List<String> BASELINE = List.of(
            "chrome.exe", "explorer.exe", "svchost.exe", "Teams.exe", "Code.exe", "outlook.exe");

    /** 배경 소음용 정상 목적지. */
    private static final List<String> BASELINE_IPS = List.of("142.250.76.14", "20.42.65.92", "13.107.42.14");

    /**
     * 과거에 있었던 것으로 꾸밀 탐지 건. hoursAgo 는 nowTs 기준 몇 시간 전인지다.
     * 최근일수록 촘촘하게 두어 "요즘 활발한 침해"처럼 보이게 한다.
     */
    private record Incident(String host, String ruleId, int hoursAgo) {
    }

    private static final List<Incident> INCIDENTS = List.of(
            new Incident("DESKTOP-KIM", "DOWNLOAD_AND_EXECUTE", 2),
            new Incident("DESKTOP-LEE", "SUSPICIOUS_PROCESS_CHAIN", 5),
            new Incident("DESKTOP-KIM", "SUSPICIOUS_PROCESS_CHAIN", 9),
            new Incident("LAPTOP-PARK", "SUSPICIOUS_PROCESS_CHAIN", 20),
            new Incident("DESKTOP-CHOI", "DOWNLOAD_AND_EXECUTE", 26),
            new Incident("DESKTOP-CHOI", "FILE_IN_AUTORUN_PATH", 27),
            new Incident("LAPTOP-PARK", "SCRIPT_FROM_TEMP_PATH", 45),
            new Incident("DESKTOP-LEE", "SCRIPT_FROM_TEMP_PATH", 52),
            new Incident("LAPTOP-PARK", "FILE_IN_AUTORUN_PATH", 120),
            new Incident("DESKTOP-KIM", "SCRIPT_FROM_TEMP_PATH", 150));

    private DemoData() {
    }

    /** 관측 호스트 전체(alert 있는 호스트 + 정상 호스트). */
    public static List<String> hosts() {
        List<String> all = new ArrayList<>(NOISY_HOSTS);
        all.addAll(QUIET_HOSTS);
        return List.copyOf(all);
    }

    /** 과거 구간의 events. 배경 소음 + 각 탐지 건의 근거 이벤트를 함께 담는다. */
    public static List<DemoEvent> events(String tenantId, long nowTs) {
        List<DemoEvent> out = new ArrayList<>(baseline(tenantId, nowTs));
        for (Incident incident : INCIDENTS) {
            out.addAll(evidence(incident, tenantId, nowTs));
        }
        return List.copyOf(out);
    }

    /** 과거 구간의 alerts. 각 건의 마지막 근거 이벤트 시각을 판정 시각으로 쓴다(detector 와 동일). */
    public static List<Alert> alerts(String tenantId, long nowTs) {
        List<Alert> out = new ArrayList<>();
        for (Incident incident : INCIDENTS) {
            out.add(alertOf(incident, tenantId, nowTs));
        }
        return List.copyOf(out);
    }

    /** 모든 호스트에 6시간 간격으로 깔리는 평상시 활동. 호스트마다 분 단위로 어긋내 한 시각에 몰리지 않게 한다. */
    private static List<DemoEvent> baseline(String tenantId, long nowTs) {
        List<DemoEvent> out = new ArrayList<>();
        List<String> hosts = hosts();
        for (int h = 0; h < hosts.size(); h++) {
            String host = hosts.get(h);
            for (int hoursAgo = 6; hoursAgo < DAYS * 24; hoursAgo += 6) {
                long ts = nowTs - hoursAgo * HOUR + h * MINUTE;
                int seed = h + hoursAgo;
                out.add(DemoEvent.of(host, tenantId, DemoEvent.TYPE_PROCESS, ts,
                        pick(BASELINE, seed), "explorer.exe", "C:\\Program Files\\" + pick(BASELINE, seed)));
                if (seed % 3 == 0) {
                    out.add(DemoEvent.network(host, tenantId, ts + 30_000,
                            pick(BASELINE, seed), pick(BASELINE_IPS, seed), 443));
                }
            }
        }
        return out;
    }

    /**
     * 탐지 건의 근거 이벤트. detector 룰이 보는 패턴 그대로 만들어야 lineage 그래프가 자연스럽게 이어진다.
     * 시퀀스 룰은 1초 간격 2건, point 룰은 1건이다.
     */
    private static List<DemoEvent> evidence(Incident incident, String tenantId, long nowTs) {
        String host = incident.host();
        long ts = nowTs - incident.hoursAgo() * HOUR;
        return switch (incident.ruleId()) {
            case "SUSPICIOUS_PROCESS_CHAIN" -> List.of(
                    DemoEvent.of(host, tenantId, DemoEvent.TYPE_PROCESS, ts,
                            "winword.exe", "explorer.exe", "\"C:\\docs\\invoice.docm\""),
                    DemoEvent.of(host, tenantId, DemoEvent.TYPE_PROCESS, ts + 1000,
                            "powershell.exe", "winword.exe", "powershell -enc SQBFAFgA..."));
            case "DOWNLOAD_AND_EXECUTE" -> List.of(
                    // network 이벤트에도 소유 프로세스를 담아야 lineage 가 process -> net 으로 이어진다
                    DemoEvent.network(host, tenantId, ts, "chrome.exe", "185.220.101.5", 443),
                    DemoEvent.of(host, tenantId, DemoEvent.TYPE_PROCESS, ts + 1000,
                            "update32.exe", "explorer.exe", "C:\\Users\\Public\\update32.exe"));
            case "SCRIPT_FROM_TEMP_PATH" -> List.of(
                    DemoEvent.of(host, tenantId, DemoEvent.TYPE_SCRIPT, ts,
                            "powershell.exe", "explorer.exe",
                            "powershell -File C:\\Users\\victim\\Downloads\\setup.ps1"));
            case "FILE_IN_AUTORUN_PATH" -> List.of(
                    DemoEvent.of(host, tenantId, DemoEvent.TYPE_FILE, ts, "evil.lnk", "",
                            "C:\\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows"
                                    + "\\Start Menu\\Programs\\Startup\\evil.lnk"));
            default -> throw new IllegalStateException("근거 이벤트가 정의되지 않은 룰: " + incident.ruleId());
        };
    }

    /** 근거 이벤트에서 alert 를 만든다. matched 문자열 형식은 detector 의 Rules.summary 와 맞춘다. */
    private static Alert alertOf(Incident incident, String tenantId, long nowTs) {
        List<DemoEvent> evidence = evidence(incident, tenantId, nowTs);
        DemoEvent last = evidence.get(evidence.size() - 1);
        String severity = severityOf(incident.ruleId());
        return new Alert(
                incident.host(),
                incident.ruleId(),
                mitreOf(incident.ruleId()),
                severity,
                actionFor(severity),
                last.ts(),
                evidence.stream().map(DemoData::summary).toList(),
                tenantId);
    }

    /** detector Rules 의 심각도와 동일하게 맞춘다. */
    private static String severityOf(String ruleId) {
        return switch (ruleId) {
            case "DOWNLOAD_AND_EXECUTE" -> "CRITICAL";
            case "SUSPICIOUS_PROCESS_CHAIN" -> "HIGH";
            default -> "MEDIUM";
        };
    }

    /** detector dto Alert.actionFor 와 동일 규칙. */
    private static String actionFor(String severity) {
        return switch (severity) {
            case "CRITICAL" -> "isolate";
            case "HIGH" -> "kill";
            default -> "notify";
        };
    }

    private static String mitreOf(String ruleId) {
        return switch (ruleId) {
            case "DOWNLOAD_AND_EXECUTE" -> "T1105+T1204";
            case "FILE_IN_AUTORUN_PATH" -> "T1547";
            default -> "T1059";
        };
    }

    /** detector Rules.summary 와 같은 형식의 판정 근거 한 줄. */
    private static String summary(DemoEvent e) {
        return switch (e.type()) {
            case DemoEvent.TYPE_NETWORK -> "network " + e.destIp() + ":" + e.destPort();
            case DemoEvent.TYPE_SCRIPT -> "script " + e.process() + " (" + e.cmdline() + ")";
            case DemoEvent.TYPE_FILE -> "file " + e.cmdline();
            default -> "process " + e.process() + " (parent " + e.parent() + ")";
        };
    }

    /** 결정적 선택. 음수 seed 는 들어오지 않지만 방어적으로 절댓값을 쓴다. */
    private static String pick(List<String> pool, int seed) {
        return pool.get(Math.abs(seed) % pool.size());
    }
}
