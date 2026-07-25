package com.edrdog.apiservice.alert;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * ruleId → 한글 위협명/카테고리 매핑 순수 로직. 미등록 ruleId 는 원문/"기타" 로 fallback.
 */
class ThreatCatalogTest {

    @Test
    void 등록된_ruleId_는_한글_이름과_카테고리를_돌려준다() {
        assertEquals("의심스러운 프로세스 실행 체인", ThreatCatalog.threatName("SUSPICIOUS_PROCESS_CHAIN"));
        assertEquals("권한상승", ThreatCatalog.category("SUSPICIOUS_PROCESS_CHAIN"));

        assertEquals("다운로드 후 실행", ThreatCatalog.threatName("DOWNLOAD_AND_EXECUTE"));
        assertEquals("악성코드", ThreatCatalog.category("DOWNLOAD_AND_EXECUTE"));

        assertEquals("임시·다운로드 경로 스크립트 실행", ThreatCatalog.threatName("SCRIPT_FROM_TEMP_PATH"));
        assertEquals("실행", ThreatCatalog.category("SCRIPT_FROM_TEMP_PATH"));

        assertEquals("자동실행 경로 파일 생성", ThreatCatalog.threatName("FILE_IN_AUTORUN_PATH"));
        assertEquals("지속성", ThreatCatalog.category("FILE_IN_AUTORUN_PATH"));
    }

    @Test
    void 미등록_ruleId_는_이름은_원문_카테고리는_기타() {
        assertEquals("UNKNOWN_RULE", ThreatCatalog.threatName("UNKNOWN_RULE"));
        assertEquals("기타", ThreatCatalog.category("UNKNOWN_RULE"));
    }

    @Test
    void null_ruleId_도_안전하게_fallback() {
        assertEquals(null, ThreatCatalog.threatName(null));
        assertEquals("기타", ThreatCatalog.category(null));
    }
}
