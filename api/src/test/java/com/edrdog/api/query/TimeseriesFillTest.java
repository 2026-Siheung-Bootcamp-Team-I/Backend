package com.edrdog.api.query;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 빈 버킷 0 채우기 순수 로직 검증. ClickHouse 없이 검증된다.
 */
class TimeseriesFillTest {

    private static final long HOUR = TimeseriesFill.HOUR_MS;
    private static final long DAY = TimeseriesFill.DAY_MS;

    @Test
    void stepFor_는_day면_하루_그외_한시간() {
        assertEquals(DAY, TimeseriesFill.stepFor("day"));
        assertEquals(HOUR, TimeseriesFill.stepFor("hour"));
        assertEquals(HOUR, TimeseriesFill.stepFor("anything"));
    }

    @Test
    void alignStart_는_시간경계로_내림() {
        // 1시간 5분 -> 1시간 경계
        assertEquals(HOUR, TimeseriesFill.alignStart(HOUR + 5 * 60_000L, HOUR));
        // 이미 경계면 그대로
        assertEquals(2 * HOUR, TimeseriesFill.alignStart(2 * HOUR, HOUR));
    }

    @Test
    void alignStart_는_일경계로_내림() {
        assertEquals(DAY, TimeseriesFill.alignStart(DAY + 3 * HOUR, DAY));
    }

    @Test
    void 빈_입력이면_from_to_사이_버킷을_모두_0으로_채운다() {
        // from=0, to=3시간 -> 3개 버킷 (0h,1h,2h) 모두 0
        List<TimeBucket> out = TimeseriesFill.fill(List.of(), 0, 3 * HOUR, HOUR);
        assertEquals(3, out.size());
        assertEquals(new TimeBucket(0, 0, 0, 0), out.get(0));
        assertEquals(new TimeBucket(HOUR, 0, 0, 0), out.get(1));
        assertEquals(new TimeBucket(2 * HOUR, 0, 0, 0), out.get(2));
    }

    @Test
    void 있는_버킷은_값을_유지하고_없는_버킷만_0으로_채운다() {
        // 가운데 버킷(1h)만 데이터 있음
        TimeBucket mid = new TimeBucket(HOUR, 2, 3, 5);
        List<TimeBucket> out = TimeseriesFill.fill(List.of(mid), 0, 3 * HOUR, HOUR);
        assertEquals(3, out.size());
        assertEquals(new TimeBucket(0, 0, 0, 0), out.get(0));
        assertEquals(mid, out.get(1));
        assertEquals(new TimeBucket(2 * HOUR, 0, 0, 0), out.get(2));
    }

    @Test
    void from_이_경계가_아니면_정렬된_시작부터_채운다() {
        // from 이 1h+10분 -> 시작 버킷은 1h
        List<TimeBucket> out = TimeseriesFill.fill(List.of(), HOUR + 10 * 60_000L, 3 * HOUR, HOUR);
        assertEquals(2, out.size());
        assertEquals(HOUR, out.get(0).bucketStart());
        assertEquals(2 * HOUR, out.get(1).bucketStart());
    }

    @Test
    void 결과는_버킷시작_오름차순() {
        List<TimeBucket> out = TimeseriesFill.fill(
                List.of(new TimeBucket(2 * HOUR, 1, 0, 1)), 0, 4 * HOUR, HOUR);
        for (int i = 1; i < out.size(); i++) {
            assertEquals(true, out.get(i - 1).bucketStart() < out.get(i).bucketStart());
        }
    }

    @Test
    void 일단위도_채운다() {
        List<TimeBucket> out = TimeseriesFill.fill(List.of(), 0, 2 * DAY, DAY);
        assertEquals(2, out.size());
        assertEquals(0, out.get(0).bucketStart());
        assertEquals(DAY, out.get(1).bucketStart());
    }
}
