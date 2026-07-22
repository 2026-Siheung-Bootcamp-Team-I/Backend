package com.edrdog.apiservice.web;

import com.edrdog.apiservice.auth.service.AuthService;
import com.edrdog.apiservice.auth.service.Principal;
import com.edrdog.apiservice.clickhouse.ClickHouseReader;
import com.edrdog.apiservice.query.EventQueryBuilder;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * ClickHouse(edrdog.events) 조회·요약을 프론트에 제공하는 읽기 전용 REST.
 * 모든 요청은 세션 Bearer 토큰으로 인증하고, 그 토큰의 tenant 로만 조회를 격리한다("A사는 A사 것만").
 */
@RestController
@RequestMapping("/api")
@Tag(name = "events", description = "이벤트 조회 및 요약 (ClickHouse, tenant 격리)")
public class EventQueryController {

    private static final String BEARER_PREFIX = "Bearer ";

    private final ClickHouseReader reader;
    private final EventQueryBuilder builder;
    private final AuthService auth;

    public EventQueryController(ClickHouseReader reader, EventQueryBuilder builder, AuthService auth) {
        this.reader = reader;
        this.builder = builder;
        this.auth = auth;
    }

    @Operation(summary = "이벤트 조회",
            description = "로그인 유저의 tenant 것만 host/type/from/to(epoch millis) 필터로 최신순 조회. limit 기본 100, 상한 1000.")
    @GetMapping("/events")
    public List<Map<String, Object>> events(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @RequestParam(required = false) String host,
            @RequestParam(required = false) String type,
            @RequestParam(required = false) Long from,
            @RequestParam(required = false) Long to,
            @RequestParam(required = false) Integer limit) {
        String tenantId = currentTenantId(authorization);
        return reader.query(builder.events(tenantId, host, type, from, to, limit));
    }

    @Operation(summary = "이벤트 요약",
            description = "로그인 유저의 tenant 것만 시간범위(from/to, epoch millis) 안에서 type 별 건수로 집계하고 총합을 함께 준다.")
    @GetMapping("/events/summary")
    public Map<String, Object> summary(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @RequestParam(required = false) Long from,
            @RequestParam(required = false) Long to) {
        String tenantId = currentTenantId(authorization);
        List<Map<String, Object>> byType = reader.query(builder.summaryByType(tenantId, from, to));
        long total = byType.stream()
                .mapToLong(row -> Long.parseLong(String.valueOf(row.get("cnt"))))
                .sum();
        return Map.of("total", total, "byType", byType);
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
