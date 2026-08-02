package com.edrdog.apiservice.query;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * timeseries 빈 버킷 0 채우기(순수 로직). DB 는 데이터가 있는 버킷만 돌려주므로 없는 구간을 여기서 메운다.
 */
public final class TimeseriesFill {

    public static final long HOUR_MS = 3_600_000L;
    public static final long DAY_MS = 86_400_000L;

    private TimeseriesFill() {
    }

    public static long stepFor(String bucket) {
        return "day".equals(bucket) ? DAY_MS : HOUR_MS;
    }

    // 버킷 경계는 UTC 기준(epoch 0 = UTC 자정/정시). AlertQueryBuilder.timeseries 의 intDiv 와 어긋나면 채운 칸이 밀린다.
    public static long alignStart(long epochMillis, long step) {
        return Math.floorDiv(epochMillis, step) * step;
    }

    /** from(정렬 후)부터 to 직전까지 step 간격 버킷을 만들고, rows 에 없는 버킷은 0 으로 채워 시간순으로 돌려준다. */
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
