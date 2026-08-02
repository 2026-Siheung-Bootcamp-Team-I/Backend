package com.edrdog.apiservice.search.web;

import java.util.List;

/**
 * 검색 결과의 한 종류(알림/호스트/이벤트) 묶음.
 * hasMore 가 없으면 조사하는 사람이 잘린 목록을 전부라고 읽는다. 종류가 셋이라 헤더 한 벌로는 어느 섹션이 잘렸는지 못 말한다.
 *
 * @param items   상한까지 잘라낸 결과
 * @param hasMore 상한 때문에 잘렸는지
 */
public record SearchSection<T>(List<T> items, boolean hasMore) {

    /** 상한보다 한 건 더 읽어 온 결과에서 탐침 행을 잘라내고 잘렸는지를 함께 남긴다(총 건수를 세지 않는다). */
    public static <T> SearchSection<T> of(List<T> found, int limit) {
        boolean hasMore = found.size() > limit;
        return new SearchSection<>(List.copyOf(hasMore ? found.subList(0, limit) : found), hasMore);
    }
}
