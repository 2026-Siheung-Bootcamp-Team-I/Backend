package com.edrdog.apiservice.web;

import org.springframework.http.ResponseEntity;

import java.util.List;

/**
 * 목록 조회의 페이지 정보를 싣는 응답 헤더. 본문은 배열 그대로 두고 페이지 정보만 헤더로 내보낸다.
 *
 * <p>헤더 이름은 프론트와의 계약이라 바꾸면 화면이 페이지 정보를 못 읽는다.
 * <p>브라우저가 읽으려면 CorsConfig 의 exposedHeaders 에 그대로 올라가 있어야 한다.
 * 안 올리면 서버는 정상인데 화면에서만 값이 안 보인다.
 */
public final class PageHeaders {

    /** 필터를 만족하는 전체 건수. 세는 비용이 있어 withTotal=true 로 요청했을 때만 붙는다. */
    public static final String TOTAL_COUNT = "X-Total-Count";

    /** 다음 페이지 존재 여부("true"/"false"). 한 행을 더 읽어 판단하므로 항상 붙는다. */
    public static final String HAS_MORE = "X-Has-More";

    /** 이 응답에 실제로 적용된 시간 하한(epoch millis). 0 이면 하한이 없다는 뜻이다. */
    public static final String TIME_FROM = "X-Time-From";

    /**
     * 이 응답에 실제로 적용된 시간 상한(epoch millis).
     * 다음 페이지를 부를 때 to 에 이 값을 그대로 안 실으면 새 이벤트가 맨 위에 쌓여 offset 이 밀린다.
     */
    public static final String TIME_TO = "X-Time-To";

    /** CorsConfig 가 그대로 노출하는 목록. 헤더를 늘리고 여기 안 넣으면 화면에서만 안 보인다. */
    public static final List<String> ALL = List.of(TOTAL_COUNT, HAS_MORE, TIME_FROM, TIME_TO);

    private PageHeaders() {
    }

    /** 페이지 정보를 헤더에 싣는다. total 이 null 이면 총계 헤더를 붙이지 않는다. */
    public static <T> ResponseEntity<List<T>> body(List<T> items, boolean hasMore, Long total,
                                                   long appliedFrom, long appliedTo) {
        ResponseEntity.BodyBuilder res = ResponseEntity.ok()
                .header(HAS_MORE, String.valueOf(hasMore))
                .header(TIME_FROM, String.valueOf(appliedFrom))
                .header(TIME_TO, String.valueOf(appliedTo));
        if (total != null) {
            res.header(TOTAL_COUNT, String.valueOf(total));
        }
        return res.body(items);
    }
}
