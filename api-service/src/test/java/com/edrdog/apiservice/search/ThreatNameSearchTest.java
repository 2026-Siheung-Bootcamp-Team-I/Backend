package com.edrdog.apiservice.search;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 한글 위협명 → ruleId 역인덱스(순수) 검증.
 * 화면에 보이는 건 한글 위협명인데 ClickHouse 에는 영문 ruleId 만 적재되므로,
 * 사람이 본 대로 친 말이 조회에 닿으려면 여기서 옮겨야 한다.
 * 영문 ruleId 자체는 SQL 이 직접 훑으므로 여기서 또 다루지 않는다.
 */
class ThreatNameSearchTest {

    @Test
    void 한글_위협명의_일부로_ruleId_를_찾는다() {
        assertEquals(List.of("DOWNLOAD_AND_EXECUTE"), SearchService.threatRuleIds("다운로드 후"));
    }

    @Test
    void 여러_위협명에_걸리면_전부_찾는다() {
        List<String> ids = SearchService.threatRuleIds("다운로드");
        assertTrue(ids.contains("DOWNLOAD_AND_EXECUTE"), ids.toString());
        assertTrue(ids.contains("SCRIPT_FROM_TEMP_PATH"), ids.toString());
    }

    @Test
    void 걸리는_위협명이_없으면_빈_목록() {
        assertTrue(SearchService.threatRuleIds("gimdong").isEmpty());
    }
}
