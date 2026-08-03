package com.edrdog.apiservice.alert;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ruleId → 한글 위협명/카테고리/MITRE/설명 매핑 순수 로직. 미등록 ruleId 는 이름/원문, 카테고리/"기타",
 * mitre·description/null 로 fallback.
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
    void 등록된_ruleId_는_mitre_태그와_설명을_돌려준다() {
        assertEquals("T1059", ThreatCatalog.mitre("SUSPICIOUS_PROCESS_CHAIN"));
        assertEquals("T1105+T1204", ThreatCatalog.mitre("DOWNLOAD_AND_EXECUTE"));
        assertEquals("T1059", ThreatCatalog.mitre("SCRIPT_FROM_TEMP_PATH"));
        assertEquals("T1547", ThreatCatalog.mitre("FILE_IN_AUTORUN_PATH"));

        // 설명 문구 자체을 전부 고정하면 사소한 표현 수정에도 테스트가 깨지므로, 발화 조건의 핵심만 포함 여부로 검증한다.
        assertTrue(ThreatCatalog.description("DOWNLOAD_AND_EXECUTE").contains("실행된 파일 자체"));
    }

    @Test
    void 미등록_ruleId_는_이름은_원문_카테고리는_기타() {
        assertEquals("UNKNOWN_RULE", ThreatCatalog.threatName("UNKNOWN_RULE"));
        assertEquals("기타", ThreatCatalog.category("UNKNOWN_RULE"));
        assertNull(ThreatCatalog.mitre("UNKNOWN_RULE"));
        assertNull(ThreatCatalog.description("UNKNOWN_RULE"));
    }

    @Test
    void null_ruleId_도_안전하게_fallback() {
        assertEquals(null, ThreatCatalog.threatName(null));
        assertEquals("기타", ThreatCatalog.category(null));
        assertNull(ThreatCatalog.mitre(null));
        assertNull(ThreatCatalog.description(null));
    }

    @Test
    void all_은_등록된_룰을_ruleId_포함해_돌려준다() {
        var entries = ThreatCatalog.all();

        assertEquals(5, entries.size());
        assertTrue(entries.stream().allMatch(e ->
                e.ruleId() != null && e.threatName() != null && e.mitre() != null && e.description() != null));
    }
}
