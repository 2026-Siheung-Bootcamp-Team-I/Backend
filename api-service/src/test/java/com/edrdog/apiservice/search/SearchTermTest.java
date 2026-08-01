package com.edrdog.apiservice.search;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 질의어 정규화·부분일치 판정(순수) 검증.
 * 상단바에 친 문자열이 그대로 전체 스캔으로 흘러가는 자리라, 너무 짧은 질의어를 여기서 막는다.
 */
class SearchTermTest {

    @Test
    void 질의어가_없으면_거절한다() {
        assertThrows(IllegalArgumentException.class, () -> SearchTerm.normalize(null));
        assertThrows(IllegalArgumentException.class, () -> SearchTerm.normalize(""));
        assertThrows(IllegalArgumentException.class, () -> SearchTerm.normalize("   "));
    }

    @Test
    void 최소_길이보다_짧으면_거절한다() {
        // 한 글자는 사실상 전부와 일치해서 결과가 쓸모없고 스캔만 돈다.
        assertThrows(IllegalArgumentException.class, () -> SearchTerm.normalize("a"));
        assertThrows(IllegalArgumentException.class, () -> SearchTerm.normalize(" a "));
    }

    @Test
    void 최소_길이면_통과한다() {
        assertEquals("ls", SearchTerm.normalize("ls"));
    }

    @Test
    void 앞뒤_공백만_떼고_대소문자는_그대로_둔다() {
        // 소문자로 접지 않는 이유는 대소문자 무관 비교를 조회 쪽에서 하기 때문이다.
        assertEquals("Gimdong", SearchTerm.normalize("  Gimdong  "));
    }

    @Test
    void 지나치게_긴_질의어는_거절한다() {
        assertThrows(IllegalArgumentException.class,
                () -> SearchTerm.normalize("a".repeat(SearchTerm.MAX_LENGTH + 1)));
        assertEquals("a".repeat(SearchTerm.MAX_LENGTH),
                SearchTerm.normalize("a".repeat(SearchTerm.MAX_LENGTH)));
    }

    @Test
    void 부분일치로_판정한다() {
        assertTrue(SearchTerm.matches("gimdonghyeon-ui-MacBookPro.local", "gimdong"));
        assertFalse(SearchTerm.matches("macbook-pro.local", "gimdong"));
    }

    @Test
    void 대소문자를_가리지_않는다() {
        assertTrue(SearchTerm.matches("gimdonghyeon-ui-MacBookPro.local", "GIMDONG"));
        assertTrue(SearchTerm.matches("GIMDONGHYEON", "gimdong"));
        assertTrue(SearchTerm.matches("gimdonghyeon-ui-MacBookPro.local", "macbookpro"));
    }

    @Test
    void 와일드카드_문자는_글자_그대로_본다() {
        // LIKE 를 쓰지 않으므로 %/_ 는 패턴이 아니라 찾을 글자다. 이게 뒤집히면 검색 한 번이 전체를 긁는다.
        assertFalse(SearchTerm.matches("gimdonghyeon", "%"));
        assertFalse(SearchTerm.matches("gimdonghyeon", "g%n"));
        assertTrue(SearchTerm.matches("100% cpu", "0% c"));
    }

    @Test
    void 값이_없으면_일치하지_않는다() {
        assertFalse(SearchTerm.matches(null, "gimdong"));
        assertFalse(SearchTerm.matches("", "gimdong"));
    }
}
