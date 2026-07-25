package com.edrdog.apiservice.alert;

import java.util.Map;

/**
 * ruleId → 한글 위협명/카테고리 매핑(순수). detector 가 발행하는 ruleId 를 화면 표시용으로 옮긴다.
 * 미등록 ruleId 는 이름은 원문, 카테고리는 "기타" 로 안전하게 fallback 한다(null 포함).
 */
public final class ThreatCatalog {

    static final String UNKNOWN_CATEGORY = "기타";

    /** ruleId → {한글 이름, 카테고리}. 중복 키 방지를 위해 단일 불변 Map 으로 관리한다. */
    private static final Map<String, Threat> THREATS = Map.of(
            "SUSPICIOUS_PROCESS_CHAIN", new Threat("의심스러운 프로세스 실행 체인", "권한상승"),
            "DOWNLOAD_AND_EXECUTE", new Threat("다운로드 후 실행", "악성코드"),
            "SCRIPT_FROM_TEMP_PATH", new Threat("임시·다운로드 경로 스크립트 실행", "실행"),
            "FILE_IN_AUTORUN_PATH", new Threat("자동실행 경로 파일 생성", "지속성"));

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

    /** null ruleId 는 Map.of 조회에서 NPE 가 나므로 미리 걸러 fallback 시킨다. */
    private static Threat lookup(String ruleId) {
        return ruleId == null ? null : THREATS.get(ruleId);
    }

    private record Threat(String name, String category) {
    }
}
