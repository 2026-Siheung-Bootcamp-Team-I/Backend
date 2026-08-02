package com.edrdog.apiservice.query;

/** 조회 입력 가드(공백 판정, limit 클램프, offset 절). 빌더마다 같은 규칙을 다시 쓰지 않게 한곳에 둔다. */
public final class QueryGuards {

    /** 기본 offset 상한. ClickHouse 의 OFFSET 은 건너뛸 행을 버리기 전에 실제로 읽어 키울수록 조회가 그대로 길어진다. */
    public static final int MAX_OFFSET = 10_000;

    private QueryGuards() {
    }

    public static boolean hasText(String s) {
        return s != null && !s.trim().isEmpty();
    }

    public static int clampLimit(Integer limit, int defaultLimit, int maxLimit) {
        if (limit == null || limit <= 0) {
            return defaultLimit;
        }
        return Math.min(limit, maxLimit);
    }

    /** limit 과 달리 범위 밖 offset 은 클램프하지 않고 거절한다(조용히 자르면 화면이 빈 페이지로 읽는다). */
    public static String offsetClause(Integer offset, int maxOffset) {
        if (offset == null || offset == 0) {
            return "";
        }
        if (offset < 0 || offset > maxOffset) {
            throw new IllegalArgumentException("offset 은 0..." + maxOffset + " 여야 합니다: " + offset);
        }
        return " OFFSET " + offset;
    }
}
