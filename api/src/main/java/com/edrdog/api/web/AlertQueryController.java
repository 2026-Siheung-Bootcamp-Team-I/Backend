package com.edrdog.api.web;

import com.edrdog.api.clickhouse.ClickHouseReader;
import com.edrdog.api.query.DetectionQueryBuilder;
import com.edrdog.api.query.TimeBucket;
import com.edrdog.api.query.TimeseriesFill;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Map;

/**
 * detections(탐지/알림) 기반 대시보드 추이 차트 REST. X-API-Key 인증(ApiKeyFilter) 뒤에서 처리된다.
 */
@RestController
@RequestMapping("/api")
@Tag(name = "alerts", description = "탐지 추이 집계 (ClickHouse detections)")
public class AlertQueryController {

    private static final long DAY_MS = 24 * 60 * 60 * 1000L;

    private final ClickHouseReader reader;
    private final DetectionQueryBuilder builder;

    public AlertQueryController(ClickHouseReader reader, DetectionQueryBuilder builder) {
        this.reader = reader;
        this.builder = builder;
    }

    @Operation(summary = "탐지 추이",
            description = "시간범위(from/to, epoch millis)를 bucket(hour|day) 단위로 집계. "
                    + "critical/high/전체 건수를 버킷별로 주고 빈 버킷은 0 으로 채운다. "
                    + "from/to 생략 시 최근 24시간. bucket 기본 hour.")
    @GetMapping("/alerts/timeseries")
    public List<TimeBucket> timeseries(
            @RequestParam(required = false) Long from,
            @RequestParam(required = false) Long to,
            @RequestParam(required = false, defaultValue = "hour") String bucket) {

        if (!"hour".equals(bucket) && !"day".equals(bucket)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "bucket 은 hour 또는 day 여야 한다");
        }

        long now = System.currentTimeMillis();
        long f = from != null ? from : now - DAY_MS;
        long t = to != null ? to : now;

        List<TimeBucket> rows = reader.query(builder.timeseries(f, t, bucket)).stream()
                .map(TimeBucket::fromRow)
                .toList();
        return TimeseriesFill.fill(rows, f, t, TimeseriesFill.stepFor(bucket));
    }
}
