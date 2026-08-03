package com.edrdog.apiservice.alert;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * ruleId → 한글 위협명/카테고리/MITRE/발화조건 설명 매핑(순수). 미등록 ruleId 는 원문/"기타"/null 로 fallback 한다.
 */
// 설명은 detector-service 의 Rules.java 판정 로직을 옮긴 것이라, 룰이 바뀌면 여기도 같이 바꿔야 화면이 거짓말을 하지 않는다.
public final class ThreatCatalog {

    static final String UNKNOWN_CATEGORY = "기타";

    // HashMap 으로 바꾸면 카탈로그 응답 순서가 흐트러진다(등록 순서가 그대로 노출된다).
    private static final Map<String, Threat> THREATS = catalog();

    private static Map<String, Threat> catalog() {
        Map<String, Threat> m = new LinkedHashMap<>();
        m.put("SUSPICIOUS_PROCESS_CHAIN", new Threat(
                "의심스러운 프로세스 실행 체인", "권한상승", "T1059",
                "워드·엑셀·파워포인트·아웃룩 등 오피스 앱이 자식 프로세스로 powershell/cmd/wscript/cscript/mshta 를 "
                        + "실행할 때 발화합니다(매크로 기반 침투 의심). pid/ppid 를 관측한 경우에는 프로세스 이름이 아니라 "
                        + "실제 부모-자식 계보가 이어질 때만 발화합니다."));
        m.put("DOWNLOAD_AND_EXECUTE", new Threat(
                "다운로드 후 실행", "악성코드", "T1105+T1204",
                "80/443/8080 포트로의 다운로드와, 실행된 파일 자체(인자가 아니라 실행 파일 경로)가 임시 또는 "
                        + "다운로드 경로에 있는 프로세스 실행이 시간 순으로 상관될 때 발화합니다. 단순 웹 접속이 아니라 "
                        + "받아온 파일을 실제로 실행한 경우만 잡습니다."));
        m.put("SCRIPT_FROM_TEMP_PATH", new Threat(
                "임시·다운로드 경로 스크립트 실행", "실행", "T1059",
                "스크립트 실행 이벤트에서 실행 대상 경로 인자가 임시(temp) 또는 다운로드 경로를 가리킬 때 발화합니다. "
                        + "선행 이벤트와 상관하지 않는 단일 이벤트 기반의 저심각 룰입니다."));
        m.put("FILE_IN_AUTORUN_PATH", new Threat(
                "자동실행 경로 파일 생성", "지속성", "T1547",
                "시작 프로그램(Startup), macOS LaunchAgents·LaunchDaemons, 레지스트리 Run 키 등 자동실행 경로에 파일이 생성·기록·이동될 때 "
                        + "발화합니다(재부팅 후에도 살아남는 지속성 확보 시도 의심). 같은 경로라도 삭제는 자동실행을 "
                        + "없애는 쪽이라 발화하지 않습니다."));
        return m;
    }

    private ThreatCatalog() {
    }

    /** 한글 위협명. 매핑 없으면 ruleId 원문(null 이면 null)을 그대로 반환한다. */
    public static String threatName(String ruleId) {
        Threat threat = lookup(ruleId);
        return threat == null ? ruleId : threat.name();
    }

    /** 위협 카테고리. 매핑 없으면 "기타". */
    public static String category(String ruleId) {
        Threat threat = lookup(ruleId);
        return threat == null ? UNKNOWN_CATEGORY : threat.category();
    }

    /** MITRE ATT&CK 태그. 매핑 없으면 null. */
    public static String mitre(String ruleId) {
        Threat threat = lookup(ruleId);
        return threat == null ? null : threat.mitre();
    }

    /** 발화 조건 설명. 매핑 없으면 null. */
    public static String description(String ruleId) {
        Threat threat = lookup(ruleId);
        return threat == null ? null : threat.description();
    }

    /** 등록된 전체 룰 카탈로그(등록 순서 보존). */
    public static List<Entry> all() {
        return THREATS.entrySet().stream()
                .map(e -> new Entry(e.getKey(), e.getValue().name(), e.getValue().category(),
                        e.getValue().mitre(), e.getValue().description()))
                .toList();
    }

    // null ruleId 는 Map 조회에서 NPE 가 나므로 미리 걸러 fallback 시킨다.
    private static Threat lookup(String ruleId) {
        return ruleId == null ? null : THREATS.get(ruleId);
    }

    private record Threat(String name, String category, String mitre, String description) {
    }

    /** ruleId 를 포함한 카탈로그 항목(대외 노출용). */
    public record Entry(String ruleId, String threatName, String category, String mitre, String description) {
    }
}
