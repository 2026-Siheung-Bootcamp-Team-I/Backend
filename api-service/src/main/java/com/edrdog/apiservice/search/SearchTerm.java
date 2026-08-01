package com.edrdog.apiservice.search;

import java.util.Locale;

/**
 * 상단바 질의어의 정규화와 부분일치 판정(순수).
 *
 * <p>부분일치는 인덱스를 못 쓴다. 이벤트는 조회 시점에 이미 수십만 건이라 질의어 하나가
 * 그대로 전체 스캔이므로, 결과가 쓸모없는 질의어는 조회를 돌기 전에 여기서 막는다.
 */
public final class SearchTerm {

    /**
     * 최소 길이. 한 글자는 사실상 모든 명령줄·경로에 들어 있어 상위 N건이 무작위와 다를 바 없다.
     * 스캔 비용은 글자 수와 무관하게 같으니, 막는 이유는 비용이 아니라 결과가 조사에 쓸모없어서다.
     * 두 글자는 조사에서 실제로 치는 가장 짧은 말(ls, sh, 88 같은 포트)을 살려 둔다.
     */
    public static final int MIN_LENGTH = 2;

    /** 최대 길이. 이보다 긴 질의어는 사람이 친 것이 아니라 무언가를 통째로 붙여 넣은 것이다. */
    public static final int MAX_LENGTH = 200;

    private SearchTerm() {
    }

    /**
     * 질의어를 조회에 쓸 형태로 다듬는다. 앞뒤 공백만 떼고 대소문자는 건드리지 않는다
     * (대소문자 무관 비교는 조회 쪽이 하므로 여기서 접으면 원문만 잃는다).
     * 길이가 범위를 벗어나면 조용히 자르지 않고 거절한다.
     */
    public static String normalize(String q) {
        String trimmed = q == null ? "" : q.trim();
        if (trimmed.length() < MIN_LENGTH) {
            throw new IllegalArgumentException("검색어는 " + MIN_LENGTH + "글자 이상이어야 합니다");
        }
        if (trimmed.length() > MAX_LENGTH) {
            throw new IllegalArgumentException("검색어는 " + MAX_LENGTH + "글자 이하여야 합니다");
        }
        return trimmed;
    }

    /**
     * 값이 질의어를 부분일치로 품는지. 대소문자를 가리지 않는다.
     *
     * <p>SQL 쪽 positionCaseInsensitive 와 같은 규칙이라야 한다. 호스트 목록은 SQL 이 아니라
     * 여기서 걸러지므로, 규칙이 갈리면 같은 검색어가 화면 섹션마다 다르게 걸린다.
     * 패턴 매칭이 아니므로 %/_ 는 찾을 글자 그대로다.
     */
    public static boolean matches(String value, String term) {
        return value != null && value.toLowerCase(Locale.ROOT).contains(term.toLowerCase(Locale.ROOT));
    }
}
