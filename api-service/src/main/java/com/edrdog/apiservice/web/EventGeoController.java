package com.edrdog.apiservice.web;

import com.edrdog.apiservice.auth.service.AuthService;
import com.edrdog.apiservice.auth.service.Principal;
import com.edrdog.apiservice.clickhouse.ClickHouseReader;
import com.edrdog.apiservice.geoip.GeoAggregator;
import com.edrdog.apiservice.geoip.GeoIpResolver;
import com.edrdog.apiservice.geoip.PrivateIp;
import com.edrdog.apiservice.query.EventQueryBuilder;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 목적지 IP 를 국가별로 집계해 world map 마커로 제공하는 읽기 전용 REST.
 * ClickHouse(edrdog.events)의 dest_ip 를 GeoLite2-Country 로 해석하며, 로그인 유저의 tenant 로만 격리한다.
 * mmdb 가 없으면(라이선스 키 미설정 등) 빈 배열(200)을 준다.
 */
@RestController
@RequestMapping("/api")
@Tag(name = "events", description = "이벤트 조회 및 요약 (ClickHouse, tenant 격리)")
public class EventGeoController {

    private static final String BEARER_PREFIX = "Bearer ";
    private static final long DAY_MILLIS = 24L * 60 * 60 * 1000;

    private final ClickHouseReader reader;
    private final EventQueryBuilder builder;
    private final GeoIpResolver resolver;
    private final AuthService auth;

    public EventGeoController(ClickHouseReader reader, EventQueryBuilder builder,
                             GeoIpResolver resolver, AuthService auth) {
        this.reader = reader;
        this.builder = builder;
        this.resolver = resolver;
        this.auth = auth;
    }

    @Operation(summary = "목적지 국가 지도",
            description = "로그인 유저의 tenant 것만 시간범위(from/to, epoch millis, 기본 최근 24시간) 안에서 목적지 IP 를 "
                    + "국가별로 집계해 world map 마커(국가명/좌표/건수)로 준다. GeoIP DB 가 없으면 빈 배열.")
    @GetMapping("/events/geo")
    public List<GeoAggregator.GeoPoint> geo(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @RequestParam(required = false) Long from,
            @RequestParam(required = false) Long to) {
        String tenantId = currentTenantId(authorization);
        long now = System.currentTimeMillis();
        long toMillis = to != null ? to : now;
        long fromMillis = from != null ? from : now - DAY_MILLIS;

        // mmdb 미로드면 조회 없이 빈 배열(200).
        if (!resolver.isAvailable()) {
            return List.of();
        }

        Map<String, Long> ipCounts = new LinkedHashMap<>();
        for (Map<String, Object> row : reader.query(builder.geo(tenantId, fromMillis, toMillis))) {
            String ip = String.valueOf(row.get("dest_ip"));
            if (!PrivateIp.isPublic(ip)) {
                continue;
            }
            long cnt = Long.parseLong(String.valueOf(row.get("cnt")));
            ipCounts.merge(ip, cnt, Long::sum);
        }
        return GeoAggregator.aggregate(ipCounts, resolver::countryCode);
    }

    /** Bearer 토큰을 검증해 현재 유저의 tenant 를 문자열로 반환. 토큰이 없거나 만료면 AuthService 가 401. */
    private String currentTenantId(String authorization) {
        Principal principal = auth.resolve(bearerToken(authorization));
        return String.valueOf(principal.tenantId());
    }

    /** "Bearer " 접두어를 떼서 토큰만 반환. 없으면 null. */
    private static String bearerToken(String authorization) {
        if (authorization == null || !authorization.startsWith(BEARER_PREFIX)) {
            return null;
        }
        return authorization.substring(BEARER_PREFIX.length()).trim();
    }
}
