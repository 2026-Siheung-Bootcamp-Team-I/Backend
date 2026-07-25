package com.edrdog.apiservice.query;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * timeseries 빈 버킷 0 채우기(순수 로직). DB 는 데이터가 있는 버킷만 돌려주므로,
 * 정렬된 시작 버킷부터 to 직전까지 버킷 간격만큼 걸어가며 없는 구간은 0 으로 채운다.
 * 버킷 경계는 UTC 기준(epoch 0 = UTC 자정/정시)이라 floorDiv 로 정렬한다.
 */
public final class TimeseriesFill {

    public static final long HOUR_MS = 3_600_000L;
    public static final long DAY_MS = 86_400_000L;

    private TimeseriesFill() {
    }

    /** bucket 문자열("day" 면 하루, 그 외 한 시간)의 간격(ms). */
    public static long stepFor(String bucket) {
        return "day".equals(bucket) ? DAY_MS : HOUR_MS;
    }

    /** epochMillis 를 step 경계(UTC 정시/자정)로 내림. */
    public static long alignStart(long epochMillis, long step) {
        return Math.floorDiv(epochMillis, step) * step;
    }

    /**
     * from(정렬 후)부터 to 직전까지 step 간격으로 모든 버킷을 만들고, rows 에 있는 버킷은 그 값을,
     * 없는 버킷은 0 으로 채워 시간순으로 돌려준다.
     */
    public static List<TimeBucket> fill(List<TimeBucket> rows, long from, long to, long step) {
        Map<Long, TimeBucket> byBucket = new HashMap<>();
        for (TimeBucket r : rows) {
            byBucket.put(r.bucketStart(), r);
        }
        List<TimeBucket> out = new ArrayList<>();
        for (long b = alignStart(from, step); b < to; b += step) {
            TimeBucket r = byBucket.get(b);
            out.add(r != null ? r : new TimeBucket(b, 0, 0, 0, 0));
        }
        return out;
    }
}
