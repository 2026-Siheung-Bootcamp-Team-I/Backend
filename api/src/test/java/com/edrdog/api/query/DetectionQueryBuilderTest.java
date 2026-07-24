package com.edrdog.api.query;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * detections timeseries/geo SQL 생성의 순수 로직 검증.
 * 시간범위는 UInt64 파라미터 바인딩으로만 들어가야 한다(인젝션 차단).
 */
class DetectionQueryBuilderTest {

    private final DetectionQueryBuilder builder = new DetectionQueryBuilder("edrdog.detections");

    // --- timeseries ---

    @Test
    void timeseries_는_severity_조건집계와_버킷_그룹핑을_만든다() {
        ChQuery q = builder.timeseries(1000L, 2000L, "hour");
        assertTrue(q.sql().contains("countIf(severity = 'CRITICAL') AS critical"), q.sql());
        assertTrue(q.sql().contains("countIf(severity = 'HIGH') AS high"), q.sql());
        assertTrue(q.sql().contains("count() AS count"), q.sql());
        assertTrue(q.sql().contains("GROUP BY bucketStart"), q.sql());
        assertTrue(q.sql().contains("ORDER BY bucketStart"), q.sql());
    }

    @Test
    void timeseries_from_to_는_ts_에_UInt64로_바인딩() {
        ChQuery q = builder.timeseries(1000L, 2000L, "hour");
        assertTrue(q.sql().contains("ts >= {from:UInt64}"), q.sql());
        assertTrue(q.sql().contains("ts < {to:UInt64}"), q.sql());
        assertEquals("1000", q.params().get("from"));
        assertEquals("2000", q.params().get("to"));
    }

    @Test
    void hour_는_toStartOfHour_로_버킷팅() {
        ChQuery q = builder.timeseries(0L, 1L, "hour");
        assertTrue(q.sql().contains("toStartOfHour"), q.sql());
        assertFalse(q.sql().contains("toStartOfDay"), q.sql());
    }

    @Test
    void day_는_toStartOfDay_로_버킷팅() {
        ChQuery q = builder.timeseries(0L, 1L, "day");
        assertTrue(q.sql().contains("toStartOfDay"), q.sql());
        assertFalse(q.sql().contains("toStartOfHour"), q.sql());
    }

    @Test
    void 버킷_경계는_UTC_기준이고_millis로_되돌린다() {
        ChQuery q = builder.timeseries(0L, 1L, "hour");
        assertTrue(q.sql().contains("'UTC'"), q.sql());
        assertTrue(q.sql().contains("* 1000 AS bucketStart"), q.sql());
    }

    // --- geo ---

    @Test
    void geo_는_dest_ip별_건수를_집계하고_빈IP를_제외() {
        ChQuery q = builder.geo(1000L, 2000L);
        assertTrue(q.sql().contains("SELECT dest_ip, count() AS cnt"), q.sql());
        assertTrue(q.sql().contains("dest_ip != ''"), q.sql());
        assertTrue(q.sql().contains("GROUP BY dest_ip"), q.sql());
    }

    @Test
    void geo_from_to_는_ts_에_UInt64로_바인딩() {
        ChQuery q = builder.geo(1000L, 2000L);
        assertTrue(q.sql().contains("ts >= {from:UInt64}"), q.sql());
        assertTrue(q.sql().contains("ts < {to:UInt64}"), q.sql());
        assertEquals("1000", q.params().get("from"));
        assertEquals("2000", q.params().get("to"));
    }
}
