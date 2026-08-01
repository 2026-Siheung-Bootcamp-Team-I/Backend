package com.edrdog.apiservice.search.web;

import java.util.List;

/**
 * 검색 결과의 한 종류(알림/호스트/이벤트) 묶음.
 *
 * <p>hasMore 를 본문에 싣는 이유. 상단바 드롭다운은 종류별로 몇 줄만 보여 주는데, 잘렸다는 표시가
 * 없으면 조사하는 사람이 그게 전부라고 읽는다. 목록 조회는 이걸 헤더(X-Has-More)로 내보내지만
 * 여기는 종류가 셋이라 헤더 한 벌로는 어느 섹션이 잘렸는지 말할 수 없다.
 *
 * @param items   상한까지 잘라낸 결과
 * @param hasMore 상한 때문에 잘렸는지
 */
public record SearchSection<T>(List<T> items, boolean hasMore) {

    /**
     * 상한보다 한 건 더 읽어 온 결과에서 탐침 행을 잘라내고 잘렸는지를 함께 남긴다
     * (다른 목록 조회와 같은 방식: 총 건수를 세지 않고 한 행으로 다음이 있는지 판단한다).
     */
    public static <T> SearchSection<T> of(List<T> found, int limit) {
        boolean hasMore = found.size() > limit;
        return new SearchSection<>(List.copyOf(hasMore ? found.subList(0, limit) : found), hasMore);
    }
}
