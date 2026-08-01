package com.edrdog.apiservice.search;

import com.edrdog.apiservice.search.web.SearchSection;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 종류별 섹션 자르기(순수) 검증. 상단바에서 "이게 전부" 로 읽히면 조사에서 놓치기 때문에
 * 잘라낸 사실이 반드시 응답에 남아야 한다.
 */
class SearchSectionTest {

    @Test
    void 상한_이하면_그대로_주고_더_없다고_말한다() {
        SearchSection<String> section = SearchSection.of(List.of("a", "b"), 5);
        assertEquals(List.of("a", "b"), section.items());
        assertFalse(section.hasMore());
    }

    @Test
    void 상한과_같으면_잘린_것이_아니다() {
        // 탐침 행이 없으니 딱 맞게 채운 것이고, 이걸 잘렸다고 하면 없는 다음 페이지를 가리킨다.
        SearchSection<String> section = SearchSection.of(List.of("a", "b"), 2);
        assertEquals(2, section.items().size());
        assertFalse(section.hasMore());
    }

    @Test
    void 탐침_행이_있으면_잘라내고_더_있다고_말한다() {
        SearchSection<String> section = SearchSection.of(List.of("a", "b", "c"), 2);
        assertEquals(List.of("a", "b"), section.items());
        assertTrue(section.hasMore());
    }

    @Test
    void 결과가_없으면_빈_섹션이다() {
        SearchSection<String> section = SearchSection.of(List.of(), 5);
        assertTrue(section.items().isEmpty());
        assertFalse(section.hasMore());
    }
}
