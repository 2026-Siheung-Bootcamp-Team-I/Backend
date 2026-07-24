package com.edrdog.api.web;

import com.edrdog.api.clickhouse.ClickHouseReader;
import com.edrdog.api.geoip.GeoAggregator;
import com.edrdog.api.geoip.GeoAggregator.GeoPoint;
import com.edrdog.api.geoip.GeoIpResolver;
import com.edrdog.api.query.DetectionQueryBuilder;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * detections 목적지 IP 를 국가 단위로 집계해 world map 마커로 주는 REST.
 * X-API-Key 인증(ApiKeyFilter) 뒤에서 처리된다. GeoIP 비활성 시 500 대신 빈 배열(200).
 */
@RestController
@RequestMapping("/api")
@Tag(name = "geo", description = "탐지 목적지 IP 국가 집계 (world map)")
public class EventGeoController {

    private static final long DAY_MS = 24 * 60 * 60 * 1000L;

    private final ClickHouseReader reader;
    private final DetectionQueryBuilder builder;
    private final GeoIpResolver resolver;

    public EventGeoController(ClickHouseReader reader, DetectionQueryBuilder builder, GeoIpResolver resolver) {
        this.reader = reader;
        this.builder = builder;
        this.resolver = resolver;
    }

    @Operation(summary = "탐지 목적지 국가 집계",
            description = "시간범위(from/to, epoch millis, 생략 시 최근 24시간) 안 네트워크 탐지의 목적지 IP 를 "
                    + "국가별로 합산해 {country, countryCode, lat, lng, count} 배열로 준다. "
                    + "사설/미해석 IP 는 제외. GeoIP DB 미설정 시 빈 배열.")
    @GetMapping("/events/geo")
    public List<GeoPoint> geo(
            @RequestParam(required = false) Long from,
            @RequestParam(required = false) Long to) {

        if (!resolver.isAvailable()) {
            return List.of();
        }

        long now = System.currentTimeMillis();
        long f = from != null ? from : now - DAY_MS;
        long t = to != null ? to : now;

        Map<String, Long> ipCounts = new LinkedHashMap<>();
        for (Map<String, Object> row : reader.query(builder.geo(f, t))) {
            String ip = String.valueOf(row.get("dest_ip"));
            long cnt = Long.parseLong(String.valueOf(row.get("cnt")));
            ipCounts.merge(ip, cnt, Long::sum);
        }
        return GeoAggregator.aggregate(ipCounts, resolver::countryCode);
    }
}
