package com.edrdog.api.query;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * detections(탐지/알림) 테이블 조회 SQL 을 만드는 순수 로직.
 * 시간범위(from/to, epoch millis)는 UInt64 파라미터 바인딩으로만 넣는다(인젝션 차단).
 */
@Component
public class DetectionQueryBuilder {

    private final String table;

    public DetectionQueryBuilder(
            @Value("${edrdog.clickhouse.detections-table:edrdog.detections}") String table) {
        this.table = table;
    }

    /**
     * ts(epoch millis)를 시간/일 단위 버킷으로 묶어 severity 별 건수를 집계.
     * bucket 은 "hour" 또는 "day"(그 외는 hour 취급). 버킷 경계·bucketStart 는 UTC 기준.
     */
    public ChQuery timeseries(long from, long to, String bucket) {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("from", String.valueOf(from));
        params.put("to", String.valueOf(to));

        String startFn = "day".equals(bucket) ? "toStartOfDay" : "toStartOfHour";
        // ts(millis)/1000 -> 초 단위 DateTime(UTC), 버킷 시작을 UTC 로 맞추고 epoch millis 로 되돌린다.
        String bucketExpr = "toUnixTimestamp(" + startFn + "(toDateTime(ts / 1000, 'UTC'), 'UTC')) * 1000";
        String sql = "SELECT " + bucketExpr + " AS bucketStart,"
                + " countIf(severity = 'CRITICAL') AS critical,"
                + " countIf(severity = 'HIGH') AS high,"
                + " count() AS count"
                + " FROM " + table
                + " WHERE ts >= {from:UInt64} AND ts < {to:UInt64}"
                + " GROUP BY bucketStart ORDER BY bucketStart";
        return new ChQuery(sql, params);
    }

    /**
     * 시간범위 안 네트워크 탐지의 목적지 IP 별 건수. dest_ip 가 빈 문자열(프로세스 전용 탐지)은 제외.
     * 공인 IP 필터링·국가 매핑은 Java(GeoAggregator)에서 처리한다.
     */
    public ChQuery geo(long from, long to) {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("from", String.valueOf(from));
        params.put("to", String.valueOf(to));

        String sql = "SELECT dest_ip, count() AS cnt FROM " + table
                + " WHERE ts >= {from:UInt64} AND ts < {to:UInt64} AND dest_ip != ''"
                + " GROUP BY dest_ip";
        return new ChQuery(sql, params);
    }
}
